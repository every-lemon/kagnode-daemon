//! Durable outbound scheduling for adapter-prepared encrypted snapshots.
//! This does not quiesce applications, produce plaintext snapshots or attest recovery.
use super::{
    agent::{Agent, Target},
    policy::{Admission, Policy, Readiness, admission},
    transport::read_file,
};
use crate::{auth, store::Store};
use anyhow::{Result, ensure};
use kagnode_backup_format::{MAX_MANIFEST_BYTES, Manifest, digest, identifier};
use ring::signature::Ed25519KeyPair;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub id: String,
    pub node: String,
    pub signing_key: PathBuf,
    pub manifest: PathBuf,
    pub objects: PathBuf,
    pub readiness: PathBuf,
    pub targets: Vec<Target>,
    pub policy: Policy,
    pub next_run: i64,
    pub paused: bool,
    /// Administrator-provided link budget, not a claim of measured link speed.
    pub link_bytes_per_second: u64,
}
impl Schedule {
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        ensure!(
            identifier(&self.id) && identifier(&self.node) && self.next_run >= 0,
            "Invalid schedule identity/time"
        );
        ensure!(
            !self.targets.is_empty()
                && self.targets.len() <= 32
                && self.policy.required_copies as usize <= self.targets.len(),
            "Invalid target/copy count"
        );
        ensure!(
            (1024..=1_000_000_000).contains(&self.link_bytes_per_second),
            "Set an explicit link budget"
        );
        for path in [
            &self.signing_key,
            &self.manifest,
            &self.objects,
            &self.readiness,
        ] {
            ensure!(
                path.is_absolute()
                    && !path
                        .components()
                        .any(|p| matches!(p, std::path::Component::ParentDir)),
                "Use absolute source paths"
            );
        }
        let mut servers = std::collections::HashSet::new();
        for target in &self.targets {
            ensure!(
                identifier(&target.server)
                    && identifier(&target.site)
                    && servers.insert((&target.site, &target.server)),
                "Duplicate or invalid target"
            );
        }
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let s: Self = serde_json::from_slice(&read_file(path, true)?)?;
        s.validate()?;
        Ok(s)
    }
    pub fn gate(&self, now: i64, queued: i64) -> Result<Admission> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Observation {
            state: Readiness,
            observed_at: i64,
        }
        let o: Observation = serde_json::from_slice(&read_file(&self.readiness, true)?)?;
        Ok(admission(
            o.state,
            o.observed_at,
            now,
            now.saturating_sub(queued).max(0) as u64,
            false,
            &self.policy,
        ))
    }
    pub fn prepared(&self) -> Result<Manifest> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.manifest)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.len() <= MAX_MANIFEST_BYTES as u64
                && m.mode() & 0o077 == 0
                && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
            "Unsafe prepared manifest"
        );
        let mut data = Vec::new();
        file.take(MAX_MANIFEST_BYTES as u64 + 1)
            .read_to_end(&mut data)?;
        let m: Manifest = serde_json::from_slice(&data)?;
        m.bytes()?;
        ensure!(
            m.node == self.node && self.targets.iter().all(|t| t.site == m.site),
            "Prepared snapshot identity mismatch"
        );
        Ok(m)
    }
}
pub struct Queue {
    db: Connection,
    _lock: fs::File,
}
#[derive(Clone)]
pub struct Work {
    pub id: i64,
    pub manifest: Manifest,
    pub schedule: Schedule,
    pub target: Target,
    pub queued: i64,
}
impl Queue {
    pub fn open(root: &Path) -> Result<Self> {
        super::repository::private(root, true)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("queue.lock"))?;
        ensure!(
            lock.metadata()?.nlink() == 1
                && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "Backup scheduler already owns the queue"
        );
        let path = root.join("queue.sqlite");
        for suffix in ["queue.sqlite", "queue.sqlite-wal", "queue.sqlite-shm"] {
            if let Ok(m) = root.join(suffix).symlink_metadata() {
                ensure!(
                    m.is_file()
                        && !m.file_type().is_symlink()
                        && m.nlink() == 1
                        && m.uid() == unsafe { libc::geteuid() }
                        && m.mode() & 0o077 == 0,
                    "Unsafe queue file"
                );
            }
        }
        let db = Connection::open(path.clone())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY,next_run INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY,schedule TEXT NOT NULL,node TEXT NOT NULL,snapshot TEXT NOT NULL,digest TEXT NOT NULL,manifest TEXT NOT NULL,config TEXT NOT NULL,queued INTEGER NOT NULL,UNIQUE(schedule,node,snapshot));
        CREATE TABLE IF NOT EXISTS transfers(id INTEGER PRIMARY KEY,job INTEGER NOT NULL,target TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL,receipt TEXT,error TEXT,UNIQUE(job,target));
        CREATE INDEX IF NOT EXISTS unfinished_jobs ON transfers(job) WHERE state!='completed';
        UPDATE transfers SET state='pending' WHERE state='running';")?;
        Ok(Self { db, _lock: lock })
    }
    pub fn enqueue_due(
        &mut self,
        config: &Schedule,
        manifest: &Manifest,
        now: i64,
    ) -> Result<bool> {
        config.validate()?;
        ensure!(
            manifest.node == config.node && config.targets.iter().all(|t| t.site == manifest.site),
            "Snapshot/schedule mismatch"
        );
        let raw = manifest.bytes()?;
        let hash = digest(&raw);
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO schedules VALUES(?1,?2)",
            params![config.id, config.next_run],
        )?;
        let due: i64 = tx.query_row(
            "SELECT next_run FROM schedules WHERE id=?1",
            [&config.id],
            |r| r.get(0),
        )?;
        if config.paused || now < due {
            return Ok(false);
        }
        let prior: Option<String> = tx
            .query_row(
                "SELECT digest FROM jobs WHERE schedule=?1 AND node=?2 AND snapshot=?3",
                params![config.id, config.node, manifest.snapshot],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = &prior {
            ensure!(
                *old == hash,
                "Prepared snapshot ID changed; retained job is immutable"
            );
        }
        if prior.is_none() {
            let count: i64 = tx.query_row("SELECT COUNT(DISTINCT job) FROM transfers WHERE state!='completed'", [], |r| r.get(0))?;
            ensure!(
                count < 1024,
                "Pending job limit reached (1024); resolve unfinished transfers before adding jobs"
            );
            tx.execute("INSERT INTO jobs(schedule,node,snapshot,digest,manifest,config,queued) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![config.id,config.node,manifest.snapshot,hash,String::from_utf8(raw)?,serde_json::to_string(config)?,now])?;
            let id = tx.last_insert_rowid();
            for target in &config.targets {
                tx.execute(
                    "INSERT INTO transfers(job,target,next_attempt) VALUES(?1,?2,?3)",
                    params![id, serde_json::to_string(target)?, now],
                )?;
            }
        }
        tx.execute(
            "UPDATE schedules SET next_run=?2 WHERE id=?1",
            params![
                config.id,
                now.checked_add(config.policy.interval_seconds as i64)
                    .ok_or_else(|| anyhow::anyhow!("Clock overflow"))?
            ],
        )?;
        tx.commit()?;
        Ok(prior.is_none())
    }
    pub fn next(&self, now: i64) -> Result<Option<Work>> {
        let row:Option<(i64,String,String,String,i64)>=self.db.query_row("SELECT t.id,j.manifest,j.config,t.target,j.queued FROM transfers t JOIN jobs j ON j.id=t.job WHERE t.state='pending' AND t.next_attempt<=?1 ORDER BY t.next_attempt,t.id LIMIT 1",[now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        row.map(|(id, m, c, t, queued)| {
            Ok(Work {
                id,
                manifest: serde_json::from_str(&m)?,
                schedule: serde_json::from_str(&c)?,
                target: serde_json::from_str(&t)?,
                queued,
            })
        })
        .transpose()
    }
    pub fn start(&self, id: i64) -> Result<()> {
        ensure!(self.db.execute("UPDATE transfers SET state='running',attempts=attempts+1 WHERE id=?1 AND state='pending'",[id])?==1,"Transfer is not pending");
        Ok(())
    }
    pub fn finish(&self, work: &Work, receipt: Option<&Value>, now: i64) -> Result<()> {
        if let Some(r) = receipt {
            ensure!(
                r["snapshot"] == work.manifest.snapshot
                    && r["server"] == work.target.server
                    && r["ciphertext_verified"] == true
                    && r["verified_at"]
                        .as_i64()
                        .is_some_and(|t| t >= 0 && t <= now + 300),
                "Invalid server receipt"
            );
            ensure!(self.db.execute("UPDATE transfers SET state='completed',receipt=?2,error=NULL WHERE id=?1 AND state='running'",params![work.id,serde_json::to_string(r)?])?==1,"Transfer is not running");
        } else {
            let attempts: u32 = self.db.query_row(
                "SELECT attempts FROM transfers WHERE id=?1",
                [work.id],
                |r| r.get(0),
            )?;
            let delay = (30i64.saturating_mul(1i64 << attempts.min(10))).min(3600);
            ensure!(self.db.execute("UPDATE transfers SET state=?2,next_attempt=?3,error='Transfer interrupted/refused; inspect identity, quota, lease and source health' WHERE id=?1 AND state='running'",params![work.id,if attempts>=10 {"blocked"} else {"pending"},now+delay])?==1,"Transfer is not running");
        }
        Ok(())
    }
    pub fn status(&self) -> Result<Value> {
        let mut stmt=self.db.prepare("SELECT t.id,j.snapshot,t.state,t.attempts,t.next_attempt,t.receipt,t.error FROM transfers t JOIN jobs j ON j.id=t.job ORDER BY t.id DESC LIMIT 64")?;
        let items=stmt.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"snapshot":r.get::<_,String>(1)?,"state":r.get::<_,String>(2)?,"attempts":r.get::<_,u32>(3)?,"next_attempt":r.get::<_,i64>(4)?,"receipt":r.get::<_,Option<String>>(5)?.and_then(|s|serde_json::from_str::<Value>(&s).ok()),"error":r.get::<_,Option<String>>(6)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(
            json!({"transfers":items,"verification":"ciphertext receipt; not recovery qualification"}),
        )
    }
}
async fn transfer(work: &Work) -> Result<Value> {
    let secret = zeroize::Zeroizing::new(read_file(&work.schedule.signing_key, true)?);
    let key = Ed25519KeyPair::from_pkcs8(&secret)
        .map_err(|_| anyhow::anyhow!("Invalid agent signing key"))?;
    let agent = Agent::new(&work.schedule.node, key, work.target.clone())?;
    let rate = work.schedule.link_bytes_per_second
        * u64::from(work.schedule.policy.bandwidth_percent)
        / 100;
    agent
        .push_limited(work.manifest.clone(), &work.schedule.objects, rate)
        .await
}
fn publish(store: &Store, state: Value) {
    if let Ok(old) = store.document("backup-agent-status") {
        if old.as_ref().is_some_and(|(_, value)| *value == state) {
            return;
        }
        let _ = store.save_document(
            "backup-agent",
            "backup-agent-status",
            old.map_or(0, |(r, _)| r),
            &state,
        );
    }
}
/// Optional worker: a private backup-agent.json enables it, independent of the dashboard.
pub async fn supervise(store: Store) -> Result<()> {
    let path = store.root.join("backup-agent.json");
    let mut queue = None;
    loop {
        let result:Result<Value>=async {
            if !path.try_exists()? { return Ok(json!({"state":"disabled"})); }
            let config=Schedule::load(&path)?;
            if queue.is_none() { queue=Some(Queue::open(&store.root.join("backup-agent"))?); }
            let q=queue.as_mut().unwrap();
            if config.paused { return Ok(json!({"state":"paused","queue":q.status()?})); }
            let prepared = config.prepared().and_then(|m| q.enqueue_due(&config, &m, auth::now()));
            let source_error = prepared.as_ref().err().map(ToString::to_string);
            if let Some(work)=q.next(auth::now())? {
                // A different schedule identity cannot silently inherit old pending work.
                ensure!(work.schedule.id==config.id && work.schedule.node==config.node,"Pending jobs belong to a different schedule");
                let gate=config.gate(auth::now(),work.queued)?;
                if !matches!(gate,Admission::Normal|Admission::Throttled) { return Ok(json!({"state":"deferred","admission":gate,"source_error":source_error,"queue":q.status()?})); }
                q.start(work.id)?;
                publish(&store,json!({"state":"transferring","source_error":source_error,"queue":q.status()?}));
                let send=transfer(&work); tokio::pin!(send);
                let result=loop {
                    tokio::select! {
                        r=&mut send => break r,
                        _=tokio::time::sleep(Duration::from_secs(1)) => {
                            let allowed=Schedule::load(&path).is_ok_and(|c| !c.paused && c.id==config.id && c.node==config.node && c.gate(auth::now(),work.queued).is_ok_and(|g| matches!(g,Admission::Normal|Admission::Throttled)));
                            if !allowed { break Err(anyhow::anyhow!("Schedule paused or readiness expired")); }
                        }
                    }
                };
                if q.finish(&work,result.as_ref().ok(),auth::now()).is_err() { q.finish(&work,None,auth::now())?; }
            }
            Ok(json!({"state":if prepared.is_ok() { "scheduled" } else { "source_blocked" },"error":source_error,"queue":q.status()?}))
        }.await;
        publish(
            &store,
            result.unwrap_or_else(|e| json!({"state":"blocked","error":e.to_string()})),
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
