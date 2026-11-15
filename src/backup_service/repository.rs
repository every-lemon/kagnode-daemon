use super::policy::{ArrayHealth, Policy};
use crate::auth;
use anyhow::{Result, ensure};
use kagnode_backup_format::{
    MAX_MANIFEST_BYTES, Manifest, Object, digest, hash, identifier, read_object,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub site: String,
    pub server: String,
    pub device: u64,
    pub inode: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSnapshot {
    pub manifest: Manifest,
    pub signature: String,
}
#[derive(Serialize, Deserialize)]
pub struct Lease {
    pub id: String,
    pub expires: i64,
    pub missing: Vec<Object>,
}
pub struct SignedRequest<'a> {
    pub node: &'a str,
    pub nonce: &'a str,
    pub at: i64,
    pub operation: &'a str,
    pub body: &'a [u8],
    pub signature: &'a str,
}
pub struct Repository {
    pub root: PathBuf,
    db: Connection,
    pub identity: Identity,
    _lock: fs::File,
}
fn private(root: &Path, create: bool) -> Result<()> {
    ensure!(
        root.is_absolute() && !root.components().any(|p| matches!(p, Component::ParentDir)),
        "Use an absolute protected repository path"
    );
    for p in root.ancestors().filter(|p| p.exists()) {
        let m = p.symlink_metadata()?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                && (m.mode() & 0o022 == 0 || (p == Path::new("/tmp") && m.mode() & 0o1000 != 0)),
            "Unsafe backup directory ancestor"
        );
    }
    if create {
        fs::create_dir_all(root)?;
    }
    let m = root.symlink_metadata()?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() },
        "Repository has another owner"
    );
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
fn bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() <= max,
        "Unsafe repository file"
    );
    let mut data = Vec::new();
    f.take(max + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= max, "Repository file exceeds limit");
    Ok(data)
}
impl Repository {
    pub fn create(root: &Path, site: &str, server: &str, policy: &Policy) -> Result<Self> {
        ensure!(
            identifier(site) && identifier(server),
            "Invalid site/server identity"
        );
        policy.validate()?;
        private(root, true)?;
        ensure!(
            fs::read_dir(root)?.next().is_none(),
            "Use an empty backup directory"
        );
        let m = root.metadata()?;
        let identity = Identity {
            site: site.into(),
            server: server.into(),
            device: m.dev(),
            inode: m.ino(),
        };
        write_new(
            &root.join("repository.json"),
            &serde_json::to_vec(&identity)?,
        )?;
        for dir in ["objects", "partial", "snapshots"] {
            fs::create_dir(root.join(dir))?;
            fs::set_permissions(root.join(dir), fs::Permissions::from_mode(0o700))?;
        }
        let r = Self::open(root)?;
        r.db.execute(
            "INSERT INTO policy VALUES(1,?1)",
            [serde_json::to_string(policy)?],
        )?;
        Ok(r)
    }
    pub fn open(root: &Path) -> Result<Self> {
        private(root, false)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("repository.lock"))?;
        ensure!(
            lock.metadata()?.is_file() && lock.metadata()?.nlink() == 1,
            "Unsafe repository lock"
        );
        ensure!(
            unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&lock),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } == 0,
            "Repository is already open; use its owning service"
        );
        let identity: Identity =
            serde_json::from_slice(&bounded(&root.join("repository.json"), 16384)?)?;
        let m = root.metadata()?;
        ensure!(
            identity.device == m.dev() && identity.inode == m.ino(),
            "Storage volume/directory changed; writes refused"
        );
        let path = root.join("index.sqlite");
        if path.exists() {
            let m = path.symlink_metadata()?;
            ensure!(
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.nlink() == 1
                    && m.uid() == unsafe { libc::geteuid() },
                "Unsafe repository index"
            );
        }
        let db = Connection::open(path)?;
        fs::set_permissions(root.join("index.sqlite"), fs::Permissions::from_mode(0o600))?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS policy(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,public_key TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS node_certificates(node TEXT PRIMARY KEY,fingerprint TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS request_limits(node TEXT PRIMARY KEY,second INTEGER NOT NULL,count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tickets(hash TEXT PRIMARY KEY,node TEXT NOT NULL,key TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY,node TEXT NOT NULL,snapshot TEXT NOT NULL,body TEXT NOT NULL,expires INTEGER NOT NULL,reserved INTEGER NOT NULL,finished INTEGER NOT NULL DEFAULT 0,UNIQUE(node,snapshot));
CREATE TABLE IF NOT EXISTS lease_progress(id TEXT PRIMARY KEY,started INTEGER NOT NULL,bytes INTEGER NOT NULL DEFAULT 0,renewed_bytes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS objects(node TEXT NOT NULL,hash TEXT NOT NULL,bytes INTEGER NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(node,hash));
CREATE TABLE IF NOT EXISTS object_verification(node TEXT NOT NULL,hash TEXT NOT NULL,stamp TEXT NOT NULL,verified_at INTEGER NOT NULL,PRIMARY KEY(node,hash));
CREATE TABLE IF NOT EXISTS snapshots(node TEXT NOT NULL,id TEXT NOT NULL,created INTEGER NOT NULL,body TEXT NOT NULL,pinned INTEGER NOT NULL DEFAULT 0,restore_verified INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(node,id));
CREATE TABLE IF NOT EXISTS snapshot_receipts(node TEXT NOT NULL,snapshot TEXT NOT NULL,received INTEGER NOT NULL,PRIMARY KEY(node,snapshot));
CREATE TABLE IF NOT EXISTS refs(node TEXT NOT NULL,snapshot TEXT NOT NULL,object TEXT NOT NULL,PRIMARY KEY(node,snapshot,object),FOREIGN KEY(node,snapshot) REFERENCES snapshots(node,id) ON DELETE CASCADE,FOREIGN KEY(node,object) REFERENCES objects(node,hash));
CREATE TABLE IF NOT EXISTS usage(month TEXT NOT NULL,node TEXT NOT NULL,bytes INTEGER NOT NULL,PRIMARY KEY(month,node));
CREATE TABLE IF NOT EXISTS replay(node TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(node,nonce));
CREATE TABLE IF NOT EXISTS restore_leases(id TEXT PRIMARY KEY,node TEXT NOT NULL,snapshot TEXT NOT NULL,actor TEXT NOT NULL,expires INTEGER NOT NULL,FOREIGN KEY(node,snapshot) REFERENCES snapshots(node,id));
CREATE TABLE IF NOT EXISTS tombstones(node TEXT NOT NULL,snapshot TEXT NOT NULL,at INTEGER NOT NULL,actor TEXT NOT NULL,PRIMARY KEY(node,snapshot));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL);")?;
        Ok(Self {
            root: root.into(),
            db,
            identity,
            _lock: lock,
        })
    }
    fn check_volume(&self) -> Result<()> {
        let m = self.root.symlink_metadata()?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.dev() == self.identity.device
                && m.ino() == self.identity.inode,
            "Storage mount unavailable"
        );
        Ok(())
    }
    pub fn policy(&self) -> Result<Policy> {
        Ok(serde_json::from_str(&self.db.query_row(
            "SELECT body FROM policy WHERE id=1",
            [],
            |r| r.get::<_, String>(0),
        )?)?)
    }
    pub fn save_policy(&mut self, next: &Policy, actor: &str) -> Result<()> {
        next.validate()?;
        let old = self.policy()?;
        ensure!(
            next.revision == old.revision + 1,
            "Policy changed; reload revision"
        );
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE policy SET body=?1 WHERE id=1",
            [serde_json::to_string(next)?],
        )?;
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,?2,'policy',?3)",
            params![auth::now(), actor, next.revision.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn approve_tls_node(
        &mut self,
        node: &str,
        public_key: &str,
        fingerprint: &str,
        now: i64,
    ) -> Result<String> {
        ensure!(
            identifier(node) && hash(public_key) && hash(fingerprint),
            "Invalid approved transport identity"
        );
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT fingerprint FROM node_certificates WHERE node=?1",
                [node],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            existing.as_deref().is_none_or(|v| v == fingerprint),
            "Changing node certificates requires explicit rotation; existing approval retained"
        );
        let token = auth::random()?;
        tx.execute(
            "INSERT INTO node_certificates VALUES(?1,?2) ON CONFLICT(node) DO NOTHING",
            params![node, fingerprint],
        )?;
        tx.execute(
            "INSERT INTO tickets VALUES(?1,?2,?3,?4,0)",
            params![auth::digest(&token), node, public_key, now + 600],
        )?;
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,'local-admin','approve-node',?2)",
            params![now, node],
        )?;
        tx.commit()?;
        Ok(token)
    }
    pub fn transport_identity(&self, node: &str, fingerprint: &str) -> Result<()> {
        ensure!(
            identifier(node) && hash(fingerprint),
            "Invalid transport identity"
        );
        let expected: String = self.db.query_row(
            "SELECT fingerprint FROM node_certificates WHERE node=?1",
            [node],
            |r| r.get(0),
        )?;
        ensure!(
            expected == fingerprint,
            "Certificate does not belong to the approved node"
        );
        Ok(())
    }
    pub fn rate_limit(&mut self, node: &str, now: i64) -> Result<()> {
        self.public_key(node)?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO request_limits VALUES(?1,?2,1) ON CONFLICT(node) DO UPDATE SET second=excluded.second,count=CASE WHEN second=excluded.second THEN count+1 ELSE 1 END",params![node,now])?;
        let count: i64 = tx.query_row(
            "SELECT count FROM request_limits WHERE node=?1",
            [node],
            |r| r.get(0),
        )?;
        ensure!(count <= 120, "Request rate exceeded");
        tx.commit()?;
        Ok(())
    }
    pub fn approve_node(&mut self, node: &str, public_key: &str, now: i64) -> Result<String> {
        ensure!(
            identifier(node) && hash(public_key) && now >= 0,
            "Invalid node identity"
        );
        let token = auth::random()?;
        self.db.execute(
            "INSERT INTO tickets VALUES(?1,?2,?3,?4,0)",
            params![auth::digest(&token), node, public_key, now + 600],
        )?;
        Ok(token)
    }
    pub fn enroll(&mut self, node: &str, token: &str, proof: &str, now: i64) -> Result<()> {
        ensure!(
            identifier(node) && token.len() <= 128 && proof.len() == 128,
            "Invalid enrollment request"
        );
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (key, expires, used): (String, i64, i64) = tx.query_row(
            "SELECT key,expires,used FROM tickets WHERE hash=?1 AND node=?2",
            params![auth::digest(token), node],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            used == 0 && now >= 0 && expires >= now,
            "Enrollment token expired or consumed"
        );
        let message = format!(
            "kagnode-backup-enroll/v1\n{}\n{}\n{}\n{}",
            self.identity.site, self.identity.server, node, token
        );
        verify(&key, message.as_bytes(), proof)?;
        ensure!(
            tx.query_row("SELECT COUNT(*) FROM nodes WHERE id=?1", [node], |r| r
                .get::<_, i64>(0))?
                == 0,
            "Node identity already enrolled; cloned identities cannot merge"
        );
        tx.execute(
            "INSERT INTO nodes(id,public_key) VALUES(?1,?2)",
            params![node, key],
        )?;
        tx.execute(
            "UPDATE tickets SET used=1 WHERE hash=?1",
            [auth::digest(token)],
        )?;
        private(&self.root.join("objects").join(node), true)?;
        private(&self.root.join("partial").join(node), true)?;
        private(&self.root.join("snapshots").join(node), true)?;
        tx.commit()?;
        Ok(())
    }
    pub fn revoke(&mut self, node: &str) -> Result<()> {
        let tx = self.db.transaction()?;
        ensure!(
            tx.execute("UPDATE nodes SET revoked=1 WHERE id=?1", [node])? == 1,
            "Unknown node"
        );
        tx.execute(
            "UPDATE leases SET expires=0 WHERE node=?1 AND finished=0",
            [node],
        )?;
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,'local-admin','revoke-node',?2)",
            params![auth::now(), node],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn public_key(&self, node: &str) -> Result<String> {
        Ok(self.db.query_row(
            "SELECT public_key FROM nodes WHERE id=?1 AND revoked=0",
            [node],
            |r| r.get(0),
        )?)
    }
    pub fn authenticate(&mut self, request: &SignedRequest<'_>, now: i64) -> Result<()> {
        let SignedRequest {
            node,
            nonce,
            at,
            operation,
            body,
            signature,
        } = *request;
        ensure!(
            identifier(node)
                && identifier(nonce)
                && identifier(operation)
                && at >= 0
                && now >= 0
                && at.abs_diff(now) <= 300,
            "Invalid or stale signed request"
        );
        let key = self.public_key(node)?;
        let msg = format!(
            "kagnode-backup-request/v1\n{}\n{}\n{node}\n{nonce}\n{at}\n{operation}\n{}",
            self.identity.site,
            self.identity.server,
            digest(body)
        );
        verify(&key, msg.as_bytes(), signature)?;
        self.db
            .execute("DELETE FROM replay WHERE expires<?1", [now])?;
        self.db.execute(
            "INSERT INTO replay VALUES(?1,?2,?3)",
            params![node, nonce, now + 600],
        )?;
        Ok(())
    }
    pub fn capacity(&self) -> Result<(u64, u64)> {
        self.check_volume()?;
        let name = std::ffi::CString::new(self.root.as_os_str().as_encoded_bytes())?;
        let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        ensure!(
            unsafe { libc::statvfs(name.as_ptr(), v.as_mut_ptr()) } == 0,
            "Storage capacity unavailable"
        );
        let v = unsafe { v.assume_init() };
        Ok((
            v.f_blocks.saturating_mul(v.f_frsize),
            v.f_bavail.saturating_mul(v.f_frsize),
        ))
    }
    pub fn begin(&mut self, snapshot: &SignedSnapshot, now: i64) -> Result<Lease> {
        self.check_volume()?;
        let m = &snapshot.manifest;
        let raw = m.bytes()?;
        ensure!(
            self.db.query_row(
                "SELECT COUNT(*) FROM tombstones WHERE node=?1 AND snapshot=?2",
                params![m.node, m.snapshot],
                |r| r.get::<_, i64>(0)
            )? == 0,
            "Snapshot was deleted; its identity cannot be reused"
        );
        ensure!(
            m.site == self.identity.site && m.created_at <= now + 300,
            "Snapshot belongs to another site or future clock"
        );
        let key = self.public_key(&m.node)?;
        verify(&key, &raw, &snapshot.signature)?;
        let encoded = serde_json::to_string(snapshot)?;
        ensure!(
            encoded.len() <= MAX_MANIFEST_BYTES + 1024,
            "Signed manifest too large"
        );
        let prior: Option<(String, String, i64, i64)> = self
            .db
            .query_row(
                "SELECT id,body,expires,finished FROM leases WHERE node=?1 AND snapshot=?2",
                params![m.node, m.snapshot],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        if let Some((id, body, expires, finished)) = prior {
            ensure!(body == encoded, "Snapshot ID is immutable");
            let expires = if finished == 0 && expires < now {
                self.renew(&m.node, &id, now)?
            } else {
                expires
            };
            return Ok(Lease {
                id,
                expires,
                missing: if finished != 0 {
                    vec![]
                } else {
                    self.missing(m)?
                },
            });
        }
        self.cleanup_partials(now)?;
        self.check_lease_slots(&m.node, "", now)?;
        let missing = self.missing(m)?;
        let needed = missing.iter().try_fold(0u64, |n, o| {
            n.checked_add(o.bytes)
                .ok_or_else(|| anyhow::anyhow!("Size overflow"))
        })?;
        let (total, available) = self.capacity()?;
        let p = self.policy()?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let(active,reserved):(i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM leases WHERE expires>=?1 AND finished=0",[now],|r|Ok((r.get(0)?,r.get(1)?)))?;
        ensure!(active < 2, "Backup server lease capacity is busy");
        ensure!(
            available
                .saturating_sub(p.reserve(total))
                .saturating_sub(reserved as u64)
                >= needed,
            "Insufficient space; protected backups retained"
        );
        let id = auth::random()?;
        let expires = now + 900;
        tx.execute(
            "INSERT INTO leases VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![
                id,
                m.node,
                m.snapshot,
                encoded,
                expires,
                i64::try_from(needed)?
            ],
        )?;
        tx.execute(
            "INSERT INTO lease_progress(id,started) VALUES(?1,?2)",
            params![id, now],
        )?;
        tx.commit()?;
        Ok(Lease {
            id,
            expires,
            missing,
        })
    }
    fn check_lease_slots(&self, node: &str, except: &str, now: i64) -> Result<()> {
        let (global, own): (i64, i64) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(node=?1),0) FROM leases WHERE finished=0 AND expires>=?2 AND id!=?3",
            params![node,now,except], |r| Ok((r.get(0)?,r.get(1)?)))?;
        ensure!(own == 0, "Node already holds an active upload lease");
        ensure!(global < 2, "Backup server lease capacity is busy");
        Ok(())
    }
    fn object_stamp(&self, node: &str, object: &Object) -> Result<String> {
        let m = self
            .root
            .join("objects")
            .join(node)
            .join(&object.sha256)
            .symlink_metadata()?;
        ensure!(
            m.is_file()
                && !m.file_type().is_symlink()
                && m.nlink() == 1
                && m.len() == object.bytes
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "Object metadata changed"
        );
        Ok(format!(
            "{}:{}:{}:{}:{}:{}:{}",
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ))
    }
    fn object_verified(&self, node: &str, object: &Object) -> bool {
        let Ok(stamp) = self.object_stamp(node, object) else {
            return false;
        };
        self.db.query_row("SELECT COUNT(*) FROM objects o JOIN object_verification v ON v.node=o.node AND v.hash=o.hash WHERE o.node=?1 AND o.hash=?2 AND o.bytes=?3 AND v.stamp=?4",params![node,object.sha256,object.bytes as i64,stamp],|r|r.get::<_,i64>(0)).is_ok_and(|count|count==1)
    }
    fn missing(&self, m: &Manifest) -> Result<Vec<Object>> {
        Ok(m.all_objects()
            .filter(|o| !self.object_verified(&m.node, o))
            .cloned()
            .collect())
    }
    fn lease(&self, node: &str, id: &str, now: i64) -> Result<SignedSnapshot> {
        self.public_key(node)?;
        let (body, expires, finished): (String, i64, i64) = self.db.query_row(
            "SELECT body,expires,finished FROM leases WHERE id=?1 AND node=?2",
            params![id, node],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            expires >= now && finished == 0,
            "Lease expired or completed"
        );
        Ok(serde_json::from_str(&body)?)
    }
    pub fn renew(&mut self, node: &str, id: &str, now: i64) -> Result<i64> {
        self.public_key(node)?;
        self.check_volume()?;
        let (body, finished): (String, i64) = self.db.query_row(
            "SELECT body,finished FROM leases WHERE node=?1 AND id=?2",
            params![node, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(finished == 0, "Completed lease cannot be renewed");
        self.check_lease_slots(node, id, now)?;
        let (started, bytes, renewed): (i64, i64, i64) = self.db.query_row(
            "SELECT started,bytes,renewed_bytes FROM lease_progress WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure!(
            now >= started && now - started < 86400,
            "Upload lease reached maximum lifetime; start a new snapshot"
        );
        ensure!(
            bytes > renewed,
            "Lease renewal requires durable upload progress"
        );
        let s: SignedSnapshot = serde_json::from_str(&body)?;
        let needed: u64 = self.missing(&s.manifest)?.iter().map(|o| o.bytes).sum();
        let (total, available) = self.capacity()?;
        let reserve = self.policy()?.reserve(total);
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let(active,reserved):(i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM leases WHERE expires>=?1 AND finished=0 AND id!=?2",params![now,id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        ensure!(
            active < 2
                && available
                    .saturating_sub(reserve)
                    .saturating_sub(reserved as u64)
                    >= needed,
            "Lease renewal lacks capacity"
        );
        tx.execute(
            "UPDATE leases SET expires=?1,reserved=?2 WHERE id=?3",
            params![(now + 900).min(started + 86400), i64::try_from(needed)?, id],
        )?;
        tx.execute(
            "UPDATE lease_progress SET renewed_bytes=bytes WHERE id=?1",
            [id],
        )?;
        tx.commit()?;
        Ok((now + 900).min(started + 86400))
    }
    fn check_transfer_budget(&self, node: &str, bytes: u64, now: i64) -> Result<String> {
        let date = chrono::DateTime::from_timestamp(now, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid clock"))?;
        let month = date.format("%Y-%m").to_string();
        let p = self.policy()?;
        let n: i64 = self.db.query_row(
            "SELECT COALESCE(SUM(bytes),0) FROM usage WHERE month=?1 AND node=?2",
            params![month, node],
            |r| r.get(0),
        )?;
        let all: i64 = self.db.query_row(
            "SELECT COALESCE(SUM(bytes),0) FROM usage WHERE month=?1",
            [&month],
            |r| r.get(0),
        )?;
        ensure!(
            p.monthly_node_bytes
                .or(p.monthly_server_bytes.map(|cap| cap / 2))
                .is_none_or(|cap| (n as u64).saturating_add(bytes) <= cap)
                && p.monthly_server_bytes
                    .is_none_or(|cap| (all as u64).saturating_add(bytes) <= cap),
            "Monthly transfer cap reached; administrator override required"
        );
        Ok(month)
    }
    fn partial_bytes(&self, node: &str) -> Result<u64> {
        let mut size = 0u64;
        for entry in fs::read_dir(self.root.join("partial").join(node))? {
            let m = entry?.path().symlink_metadata()?;
            ensure!(
                m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1,
                "Unsafe partial object"
            );
            size = size
                .checked_add(m.len())
                .ok_or_else(|| anyhow::anyhow!("Partial size overflow"))?;
        }
        Ok(size)
    }
    /// Fixed conservative limits until administrator-configured storage quotas are qualified.
    fn check_node_storage(&self, node: &str, more: u64) -> Result<()> {
        let partial = self.partial_bytes(node)?;
        ensure!(
            partial.saturating_add(more) <= 64 * 1024 * 1024,
            "Node partial-upload quota reached"
        );
        let stored: i64 = self.db.query_row(
            "SELECT COALESCE(SUM(bytes),0) FROM objects WHERE node=?1",
            [node],
            |r| r.get(0),
        )?;
        ensure!(
            (stored as u64).saturating_add(partial).saturating_add(more) <= 1024u64.pow(4),
            "Node storage quota reached"
        );
        Ok(())
    }
    fn cleanup_partials(&self, now: i64) -> Result<usize> {
        let mut removed = 0;
        for dir in fs::read_dir(self.root.join("partial"))? {
            let dir = dir?;
            let node = dir.file_name().to_string_lossy().into_owned();
            ensure!(
                identifier(&node) && dir.file_type()?.is_dir(),
                "Unsafe partial node directory"
            );
            for entry in fs::read_dir(dir.path())? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                // IDs are hexadecimal, but use the rightmost delimiter for compatibility.
                let Some((lease, object)) = name.rsplit_once('-') else {
                    continue;
                };
                if !identifier(lease) || !hash(object) {
                    continue;
                }
                let active: i64 = self.db.query_row("SELECT COUNT(*) FROM leases WHERE id=?1 AND node=?2 AND finished=0 AND expires>=?3", params![lease,node,now], |r|r.get(0))?;
                if active == 0 {
                    ensure!(entry.file_type()?.is_file(), "Unsafe partial entry");
                    fs::remove_file(entry.path())?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
    pub fn offset(&self, node: &str, lease: &str, object: &str, now: i64) -> Result<u64> {
        let s = self.lease(node, lease, now)?;
        ensure!(
            s.manifest.all_objects().any(|o| o.sha256 == object),
            "Object outside lease"
        );
        let p = self
            .root
            .join("partial")
            .join(node)
            .join(format!("{lease}-{object}"));
        if !p.exists() {
            return Ok(0);
        }
        let m = p.symlink_metadata()?;
        ensure!(
            m.is_file() && !m.file_type().is_symlink() && m.nlink() == 1,
            "Unsafe partial object"
        );
        Ok(m.len())
    }
    pub fn upload(
        &mut self,
        node: &str,
        id: &str,
        object: &str,
        offset: u64,
        data: &[u8],
        now: i64,
    ) -> Result<u64> {
        self.check_volume()?;
        ensure!(
            !data.is_empty() && data.len() <= 1024 * 1024,
            "Upload chunk must be 1 byte–1 MiB"
        );
        let s = self.lease(node, id, now)?;
        let o = s
            .manifest
            .all_objects()
            .find(|o| o.sha256 == object)
            .ok_or_else(|| anyhow::anyhow!("Object outside lease"))?;
        ensure!(
            offset == self.offset(node, id, object, now)?
                && offset.saturating_add(data.len() as u64) <= o.bytes,
            "Upload offset or size conflict"
        );
        let (total, avail) = self.capacity()?;
        ensure!(
            avail.saturating_sub(self.policy()?.reserve(total)) >= data.len() as u64,
            "Storage reserve reached"
        );
        self.check_node_storage(node, data.len() as u64)?;
        // Provisional chunks consume storage quota, not accepted-transfer budget.
        let month = self.check_transfer_budget(node, o.bytes, now)?;
        let path = self
            .root
            .join("partial")
            .join(node)
            .join(format!("{id}-{object}"));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        ensure!(
            file.metadata()?.len() == offset && file.metadata()?.nlink() == 1,
            "Partial upload changed"
        );
        if let Err(error) = file.write_all(data).and_then(|_| file.sync_all()) {
            file.set_len(offset)?;
            file.sync_all()?;
            return Err(error.into());
        }
        let size = offset + data.len() as u64;
        drop(file);
        if size == o.bytes {
            let bytes = bounded(&path, o.bytes)?;
            if digest(&bytes) != object {
                fs::remove_file(&path)?;
                anyhow::bail!("Uploaded object failed checksum; partial upload discarded");
            }
            let dest = self.root.join("objects").join(node).join(object);
            if dest.exists() {
                read_object(dest.parent().unwrap(), o)?;
                fs::remove_file(path)?;
            } else {
                fs::rename(path, &dest)?;
                fs::File::open(dest.parent().unwrap())?.sync_all()?;
            }
            let stamp = self.object_stamp(node, o)?;
            let tx = self.db.transaction()?;
            let added = tx.execute(
                "INSERT OR IGNORE INTO objects VALUES(?1,?2,?3,?4)",
                params![node, object, i64::try_from(size)?, now],
            )?;
            tx.execute("INSERT INTO object_verification VALUES(?1,?2,?3,?4) ON CONFLICT(node,hash) DO UPDATE SET stamp=excluded.stamp,verified_at=excluded.verified_at", params![node,object,stamp,now])?;
            if added != 0 {
                tx.execute("INSERT INTO usage VALUES(?1,?2,?3) ON CONFLICT(month,node) DO UPDATE SET bytes=bytes+excluded.bytes", params![month,node,i64::try_from(size)?])?;
            }
            tx.commit()?;
        }
        self.db.execute(
            "UPDATE lease_progress SET bytes=bytes+?1 WHERE id=?2",
            params![data.len() as i64, id],
        )?;
        Ok(size)
    }
    pub fn finish(&mut self, node: &str, id: &str, now: i64) -> Result<Value> {
        self.check_volume()?;
        self.public_key(node)?;
        let prior: Option<String> = self
            .db
            .query_row(
                "SELECT snapshot FROM leases WHERE node=?1 AND id=?2 AND finished=1",
                params![node, id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(snapshot) = prior {
            let restored: i64 = self.db.query_row(
                "SELECT restore_verified FROM snapshots WHERE node=?1 AND id=?2",
                params![node, snapshot],
                |r| r.get(0),
            )?;
            return Ok(
                json!({"snapshot":snapshot,"ciphertext_verified":true,"restore_tested":restored!=0,"server":self.identity.server}),
            );
        }
        let s = self.lease(node, id, now)?;
        let m = &s.manifest;
        ensure!(
            self.missing(m)?.is_empty(),
            "Backup is incomplete or corrupted"
        );
        let encoded = serde_json::to_string(&s)?;
        let target = self
            .root
            .join("snapshots")
            .join(node)
            .join(format!("{}.json", m.snapshot));
        if target.exists() {
            ensure!(
                bounded(&target, (MAX_MANIFEST_BYTES + 1024) as u64)? == encoded.as_bytes(),
                "Snapshot catalog is immutable"
            );
        } else {
            write_new(&target, encoded.as_bytes())?;
            fs::File::open(target.parent().unwrap())?.sync_all()?;
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO snapshots(node,id,created,body) VALUES(?1,?2,?3,?4)",
            params![node, m.snapshot, m.created_at, encoded],
        )?;
        tx.execute(
            "INSERT INTO snapshot_receipts VALUES(?1,?2,?3)",
            params![node, m.snapshot, now],
        )?;
        for o in m.all_objects() {
            tx.execute(
                "INSERT OR IGNORE INTO objects VALUES(?1,?2,?3,?4)",
                params![node, o.sha256, i64::try_from(o.bytes)?, now],
            )?;
            tx.execute(
                "INSERT INTO refs VALUES(?1,?2,?3)",
                params![node, m.snapshot, o.sha256],
            )?;
        }
        tx.execute("UPDATE leases SET finished=1,reserved=0 WHERE id=?1", [id])?;
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,?2,'snapshot-verified',?3)",
            params![now, node, m.snapshot],
        )?;
        tx.commit()?;
        Ok(
            json!({"snapshot":m.snapshot,"ciphertext_verified":true,"restore_tested":false,"server":self.identity.server}),
        )
    }
    pub fn snapshots(&self, node: &str) -> Result<Vec<Value>> {
        ensure!(identifier(node), "Invalid node");
        let mut q=self.db.prepare("SELECT s.id,s.created,s.pinned,s.restore_verified,COALESCE(r.received,0) FROM snapshots s LEFT JOIN snapshot_receipts r ON r.node=s.node AND r.snapshot=s.id WHERE s.node=?1 ORDER BY COALESCE(r.received,0) DESC,s.rowid DESC")?;
        Ok(q.query_map([node],|r|Ok(json!({"id":r.get::<_,String>(0)?,"created":r.get::<_,i64>(1)?,"pinned":r.get::<_,i64>(2)?!=0,"restore_tested":r.get::<_,i64>(3)?!=0,"received_at":r.get::<_,i64>(4)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn protected(&self, node: &str) -> Result<Vec<String>> {
        let snapshots = self.snapshots(node)?;
        let keep = self.policy()?.keep_snapshots;
        let mut verified = 0;
        let mut protected = Vec::new();
        // Unverified arrivals cannot age out a known recovery point. Until the
        // requested number of newer restore-tested snapshots exists, retain it.
        for snapshot in &snapshots {
            if verified < keep || snapshot["pinned"] == true {
                protected.push(snapshot["id"].as_str().unwrap().to_owned());
            }
            if snapshot["restore_tested"] == true {
                verified += 1;
            }
        }
        let mut q = self
            .db
            .prepare("SELECT snapshot FROM restore_leases WHERE node=?1 AND expires>=?2")?;
        protected.extend(
            q.query_map(params![node, auth::now()], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
        Ok(protected)
    }
    /// Called only by the separately authorized administrative/restore-runner control plane.
    pub fn begin_restore(
        &mut self,
        node: &str,
        snapshot: &str,
        actor: &str,
        now: i64,
    ) -> Result<String> {
        ensure!(
            !actor.is_empty() && actor != node,
            "Restore needs separate administration authorization"
        );
        let id = auth::random()?;
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO restore_leases VALUES(?1,?2,?3,?4,?5)",
            params![id, node, snapshot, actor, now + 3600],
        )?;
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,?2,'restore-start',?3)",
            params![now, actor, snapshot],
        )?;
        tx.commit()?;
        Ok(id)
    }
    pub fn end_restore(&mut self, id: &str, actor: &str) -> Result<()> {
        ensure!(
            self.db.execute(
                "DELETE FROM restore_leases WHERE id=?1 AND actor=?2",
                params![id, actor]
            )? == 1,
            "Unknown restore lease"
        );
        Ok(())
    }
    pub fn mark_restore_tested(&mut self, node: &str, snapshot: &str, actor: &str) -> Result<()> {
        ensure!(
            !actor.is_empty() && actor != node,
            "Source agent cannot attest a restore"
        );
        let tx = self.db.transaction()?;
        ensure!(
            tx.execute(
                "UPDATE snapshots SET restore_verified=1 WHERE node=?1 AND id=?2",
                params![node, snapshot]
            )? == 1,
            "Unknown snapshot"
        );
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,?2,'restore-test',?3)",
            params![auth::now(), actor, snapshot],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn pin(&mut self, node: &str, snapshot: &str, pin: bool) -> Result<()> {
        let tx = self.db.transaction()?;
        ensure!(
            tx.execute(
                "UPDATE snapshots SET pinned=?1 WHERE node=?2 AND id=?3",
                params![pin, node, snapshot]
            )? == 1,
            "Unknown snapshot"
        );
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,'local-admin',?2,?3)",
            params![
                auth::now(),
                if pin {
                    "pin-snapshot"
                } else {
                    "unpin-snapshot"
                },
                format!("{node}/{snapshot}")
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn delete(&mut self, node: &str, snapshot: &str, actor: &str) -> Result<()> {
        ensure!(
            identifier(snapshot) && identifier(node) && !actor.is_empty() && actor != node,
            "Only the server administration plane may delete snapshots"
        );
        ensure!(
            !self.protected(node)?.iter().any(|s| s == snapshot),
            "Latest, rollback, pinned and active restore snapshots cannot be deleted"
        );
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM restore_leases WHERE expires<?1", [auth::now()])?;
        tx.execute(
            "INSERT INTO tombstones VALUES(?1,?2,?3,?4)",
            params![node, snapshot, auth::now(), actor],
        )?;
        ensure!(
            tx.execute(
                "DELETE FROM snapshots WHERE node=?1 AND id=?2",
                params![node, snapshot]
            )? == 1,
            "Unknown snapshot"
        );
        tx.execute(
            "INSERT INTO audit(at,actor,action,target) VALUES(?1,?2,'delete-snapshot',?3)",
            params![auth::now(), actor, snapshot],
        )?;
        tx.commit()?;
        fs::remove_file(
            self.root
                .join("snapshots")
                .join(node)
                .join(format!("{snapshot}.json")),
        )?;
        Ok(())
    }
    pub fn gc(&mut self, now: i64) -> Result<usize> {
        self.check_volume()?;
        self.cleanup_partials(now)?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure!(
            tx.query_row(
                "SELECT COUNT(*) FROM leases WHERE finished=0 AND expires>=?1",
                [now],
                |r| r.get::<_, i64>(0)
            )? == 0,
            "Garbage collection waits for upload leases"
        );
        let dead = {
            let mut q=tx.prepare("SELECT node,hash FROM objects WHERE created<?1 AND NOT EXISTS(SELECT 1 FROM refs WHERE refs.node=objects.node AND refs.object=objects.hash)")?;
            q.query_map([now - 86400], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (n, h) in &dead {
            match fs::remove_file(self.root.join("objects").join(n).join(h)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            tx.execute(
                "DELETE FROM objects WHERE node=?1 AND hash=?2",
                params![n, h],
            )?;
        }
        tx.commit()?;
        Ok(dead.len())
    }
    pub fn eligibility(&self, health: ArrayHealth, last_heartbeat: i64, now: i64) -> bool {
        health == ArrayHealth::Healthy
            && last_heartbeat >= 0
            && last_heartbeat <= now
            && now - last_heartbeat <= 90
    }
}
pub fn verify(public_key: &str, data: &[u8], signature: &str) -> Result<()> {
    ensure!(
        hash(public_key) && signature.len() == 128,
        "Invalid signing identity"
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, hex::decode(public_key)?)
        .verify(data, &hex::decode(signature)?)
        .map_err(|_| anyhow::anyhow!("Signature verification failed"))
}
