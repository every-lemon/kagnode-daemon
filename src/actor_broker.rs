//! Actor-bound authorization substrate. Production native dispatch is unavailable.
//! Root and controller service account are trusted; logical callers are not.
use crate::{
    auth,
    roles::{self, Principal},
    store::Store,
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

pub(crate) fn configured(_store: &Store) -> bool {
    #[cfg(test)]
    {
        _store
            .actor_test_enabled
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(not(test))]
    {
        false
    }
}
pub(crate) fn check_available(store: &Store, action: &roles::Action) -> Result<()> {
    let intent = match action {
        roles::Action::Reauthenticate { target, .. } => target.as_ref(),
        other => other,
    };
    if matches!(intent, roles::Action::BrokerIntent { .. }) {
        ensure!(configured(store), "control_unavailable");
    }
    Ok(())
}
pub const ROOT_SOCKET: &str = "/run/kagnode-daemon/actor-broker.sock";
const LIMIT: u64 = 16384;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FixedAction {
    Health,
    Logs,
    BootSet { enabled: bool },
    CorePlan,
    CoreApply,
    CoreRollback,
    BackupManage,
    BackupPin { pinned: bool },
}
impl FixedAction {
    pub fn risky(&self) -> bool {
        !matches!(self, Self::Health | Self::Logs | Self::CorePlan)
    }
    pub fn permission(&self) -> &'static str {
        match self {
            Self::Health => "product_status",
            Self::Logs => "logs",
            Self::BootSet { .. } => "boot_set",
            Self::CorePlan => "core_plan",
            Self::CoreApply => "core_apply",
            Self::CoreRollback => "core_rollback",
            Self::BackupManage => "backup_manage",
            Self::BackupPin { .. } => "backup_pin",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedRequest {
    pub request_id: String,
    pub product: String,
    pub action: FixedAction,
    /// SHA256 of the immutable reviewed adapter plan; never an arbitrary command.
    pub plan_sha256: String,
}
impl ReviewedRequest {
    pub fn valid(&self) -> Result<()> {
        ensure!(
            valid_id(&self.request_id)
                && roles::valid_product(&self.product)
                && self.plan_sha256.len() == 64
                && self
                    .plan_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Invalid reviewed request"
        );
        ensure!(
            !matches!(
                self.action,
                FixedAction::BackupManage | FixedAction::BackupPin { .. }
            ) || self.product == roles::BACKUP_PRODUCT,
            "Invalid backup scope"
        );
        Ok(())
    }
}
fn scope_key(b: &Binding) -> Result<String> {
    digest(&(
        b.installation.as_str(),
        b.actor.as_str(),
        b.request.request_id.as_str(),
    ))
}
static PENDING: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<String, Authority>>,
> = std::sync::OnceLock::new();
fn pending() -> &'static std::sync::Mutex<std::collections::BTreeMap<String, Authority>> {
    PENDING.get_or_init(Default::default)
}
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn digest(v: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(v)?)))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub installation: String,
    pub request: ReviewedRequest,
    pub actor: String,
    pub origin_uid: u32,
    pub auth_revision: i64,
    pub security_revision: i64,
    pub protection: String,
    pub expires_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    binding: Binding,
    nonce: String,
}
impl Drop for Authority {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.nonce.zeroize();
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub binding: Binding,
    pub service_uid: u32,
    pub state: String,
}

pub(crate) fn migrate(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS broker_installation(id INTEGER PRIMARY KEY CHECK(id=1),identity TEXT NOT NULL); CREATE TABLE IF NOT EXISTS broker_intents(request_id TEXT PRIMARY KEY,binding TEXT NOT NULL,nonce_hash TEXT NOT NULL UNIQUE,session_hash TEXT NOT NULL,state TEXT NOT NULL,receipt TEXT);")?;
    db.execute(
        "INSERT OR IGNORE INTO broker_installation VALUES(1,?1)",
        [auth::random()?],
    )?;
    Ok(())
}
/// Called inside the role transaction after exact one-use confirmation consumption.
pub(crate) fn issue(
    db: &Connection,
    p: &Principal,
    uid: u32,
    token: &str,
    id: &str,
    request: &ReviewedRequest,
) -> Result<Value> {
    request.valid()?;
    ensure!(
        id == request.request_id
            && roles::permits(p, request.action.permission(), Some(&request.product)),
        "Action not permitted"
    );
    ensure!(
        uid != roles::WEB_UID,
        "Native intent requires local transport"
    );
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM broker_intents WHERE json_extract(binding,'$.actor')=?1",
        [&p.id],
        |r| r.get(0),
    )?;
    ensure!(count < 256, "Actor intent history requires inspection");
    let outstanding:i64=db.query_row("SELECT COUNT(*) FROM broker_intents WHERE json_extract(binding,'$.actor')=?1 AND state IN ('pending','consumed','uncertain')",[&p.id],|r|r.get(0))?;
    ensure!(outstanding < 4, "Actor outstanding intent limit reached");
    let total: i64 = db.query_row("SELECT COUNT(*) FROM broker_intents", [], |r| r.get(0))?;
    ensure!(total < 4096, "Intent history requires inspection");
    let installation: String =
        db.query_row("SELECT identity FROM broker_installation", [], |r| r.get(0))?;
    let revision: i64 = db.query_row("SELECT revision FROM security_config", [], |r| r.get(0))?;
    let binding = Binding {
        installation,
        request: request.clone(),
        actor: p.id.clone(),
        origin_uid: uid,
        auth_revision: p.auth_revision,
        security_revision: revision,
        protection: db.query_row("SELECT mode FROM security_config", [], |r| r.get(0))?,
        expires_at: auth::now() + 30,
    };
    let authority = Authority {
        binding,
        nonce: auth::random()?,
    };
    db.execute(
        "INSERT INTO broker_intents VALUES(?1,?2,?3,?4,'pending',NULL)",
        params![
            scope_key(&authority.binding)?,
            serde_json::to_string(&authority.binding)?,
            auth::digest(&authority.nonce),
            auth::digest(token)
        ],
    )?;
    // The nonce never enters a user-visible Value. Losing this bounded transient
    // authority after restart leaves durable intent inspection-only.
    let handle = digest(&authority.binding)?;
    let mut pending = pending()
        .lock()
        .map_err(|_| anyhow::anyhow!("Authority unavailable"))?;
    pending.retain(|_, v| v.binding.expires_at > auth::now());
    ensure!(
        pending.len() < 128 && pending.values().filter(|a| a.binding.actor == p.id).count() < 4,
        "Authority workers busy"
    );
    pending.insert(handle.clone(), authority);
    Ok(json!({"broker_intent":handle}))
}

/// Fresh authorization linearization point; accepts real root peer credentials only.
fn admit(store: &Store, peer: u32, authority: &Authority) -> Result<Binding> {
    ensure!(peer == 0, "Root callback peer required");
    authority.binding.request.valid()?;
    let mut db = store.db()?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (encoded, nonce, session, state): (String, String, String, String) = tx.query_row(
        "SELECT binding,nonce_hash,session_hash,state FROM broker_intents WHERE request_id=?1",
        [scope_key(&authority.binding)?],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let b: Binding = serde_json::from_str(&encoded)?;
    ensure!(
        b == authority.binding
            && nonce == auth::digest(&authority.nonce)
            && state == "pending"
            && b.expires_at > auth::now(),
        "Authority refused"
    );
    let p = roles::principal(&tx, &b.actor)?;
    let (security, protection): (i64, String) =
        tx.query_row("SELECT revision,mode FROM security_config", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let current:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE hash=?1 AND user_id=?2 AND uid=?3 AND auth_revision=?4 AND expires>?5 AND last_use>?6 AND (?8=0 OR authenticated_at>?7))",params![session,b.actor,b.origin_uid,b.auth_revision,auth::now(),auth::now()-900,auth::now()-300,b.request.action.risky()],|r|r.get(0))?;
    ensure!(
        current
            && p.auth_revision == b.auth_revision
            && security == b.security_revision
            && protection == b.protection
            && roles::permits(&p, b.request.action.permission(), Some(&b.request.product)),
        "Authority revoked"
    );
    ensure!(
        tx.execute(
            "UPDATE broker_intents SET state='consumed' WHERE request_id=?1 AND state='pending'",
            [scope_key(&b)?]
        )? == 1,
        "Authority replayed"
    );
    roles::audit(
        &tx,
        &p.id,
        b.origin_uid,
        &protection,
        "broker_admit",
        &b.request.request_id,
        "consumed",
    )?;
    tx.commit()?;
    Ok(b)
}
pub(crate) fn retrieve(db: &Connection, p: &Principal, id: &str, product: &str) -> Result<Value> {
    ensure!(
        roles::permits(p, "product_status", Some(product)),
        "Action not permitted"
    );
    ensure!(valid_id(id), "Invalid request ID");
    let installation: String =
        db.query_row("SELECT identity FROM broker_installation", [], |r| r.get(0))?;
    let key = digest(&(installation.as_str(), p.id.as_str(), id))?;
    let (binding, state, receipt): (String, String, Option<String>) = db.query_row(
        "SELECT binding,state,receipt FROM broker_intents WHERE request_id=?1",
        [key],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let b: Binding = serde_json::from_str(&binding)?;
    ensure!(
        b.actor == p.id && b.request.product == product,
        "Receipt scope refused"
    );
    Ok(
        json!({"binding":b,"state":state,"receipt":receipt.map(|v|serde_json::from_str::<Receipt>(&v)).transpose()?}),
    )
}
fn save_receipt(store: &Store, receipt: &Receipt) -> Result<()> {
    let mut db = store.db()?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let encoded: String = tx.query_row(
        "SELECT binding FROM broker_intents WHERE request_id=?1",
        [scope_key(&receipt.binding)?],
        |r| r.get(0),
    )?;
    ensure!(
        serde_json::from_str::<Binding>(&encoded)? == receipt.binding,
        "Receipt binding refused"
    );
    ensure!(
        ["unavailable", "completed", "uncertain"].contains(&receipt.state.as_str()),
        "Invalid receipt state"
    );
    tx.execute(
        "UPDATE broker_intents SET state=?2,receipt=?3 WHERE request_id=?1",
        params![
            scope_key(&receipt.binding)?,
            receipt.state,
            serde_json::to_string(receipt)?
        ],
    )?;
    roles::audit(
        &tx,
        &receipt.binding.actor,
        receipt.binding.origin_uid,
        &receipt.binding.protection,
        "broker_result",
        &receipt.binding.request.request_id,
        &receipt.state,
    )?;
    tx.commit()?;
    Ok(())
}

fn protected_parent(path: &Path, uid: u32) -> Result<()> {
    for parent in path.ancestors().skip(1) {
        let m = parent.symlink_metadata()?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && (m.uid() == 0 || m.uid() == uid)
                && (m.mode() & 0o022 == 0
                    || (parent == Path::new("/tmp") && m.uid() == 0 && m.mode() & 0o1000 != 0)),
            "Unsafe authority directory"
        );
    }
    Ok(())
}
fn connect_bounded(
    path: &Path,
    timeout: Duration,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid authority socket",
        ));
    }
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as libc::c_char;
    }
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let start = std::time::Instant::now();
        loop {
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Authority connect deadline",
                ));
            }
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let result = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    left.as_millis().max(1).min(i32::MAX as u128) as i32,
                )
            };
            if result < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if result == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Authority connect deadline",
                ));
            }
            let mut error = 0i32;
            let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut i32).cast(),
                    &mut len,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if error != 0 {
                return Err(std::io::Error::from_raw_os_error(error));
            }
            break;
        }
    }
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}
fn listen(path: &Path, uid: u32) -> Result<UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    protected_parent(path, uid)?;
    match path.symlink_metadata() {
        Ok(before) => {
            ensure!(
                before.file_type().is_socket() && before.uid() == uid && before.mode() & 0o077 == 0,
                "Unsafe existing authority socket"
            );
            let error = connect_bounded(path, Duration::from_millis(150))
                .err()
                .ok_or_else(|| anyhow::anyhow!("Authority listener already active"))?;
            ensure!(
                error.raw_os_error() == Some(libc::ECONNREFUSED),
                "Authority listener state requires inspection"
            );
            let after = path.symlink_metadata()?;
            ensure!(
                after.dev() == before.dev()
                    && after.ino() == before.ino()
                    && after.file_type().is_socket()
                    && after.uid() == uid
                    && after.mode() & 0o077 == 0,
                "Authority socket changed during inspection"
            );
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
async fn read<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        (&mut reader).take(LIMIT + 1).read_line(&mut line),
    )
    .await??;
    ensure!(
        line.len() <= LIMIT as usize && line.ends_with('\n'),
        "Authority frame refused"
    );
    let result = serde_json::from_str(&line);
    use zeroize::Zeroize;
    line.zeroize();
    Ok(result?)
}
async fn write(stream: &mut UnixStream, v: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(v)?;
    ensure!(
        bytes.len() <= LIMIT as usize,
        "Authority response exceeded bounds"
    );
    bytes.push(b'\n');
    let result = tokio::time::timeout(Duration::from_secs(2), stream.write_all(&bytes)).await;
    use zeroize::Zeroize;
    bytes.zeroize();
    result??;
    Ok(())
}
/// Separate callback workers cannot be occupied by controller requests waiting on root.
/// It must be hosted in a protected private directory; no public route calls admit.
pub(crate) fn authority_listener(store: &Store) -> Result<UnixListener> {
    let run = store.root.join("run");
    if !run.exists() {
        std::fs::create_dir(&run)?;
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))?;
    }
    listen(&run.join("authority.sock"), unsafe { libc::geteuid() })
}
pub async fn serve_authority(store: Store) -> Result<()> {
    let listener = authority_listener(&store)?;
    serve_authority_on(store, listener).await
}
pub(crate) async fn serve_authority_on(store: Store, listener: UnixListener) -> Result<()> {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(cred) = stream.peer_cred() else {
            continue;
        };
        let peer = cred.uid();
        if peer != 0 {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let store = store.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                let authority: Authority = read(&mut stream).await?;
                let b =
                    tokio::task::spawn_blocking(move || admit(&store, peer, &authority)).await??;
                Ok::<_, anyhow::Error>(b)
            }
            .await;
            // Deliberately generic: no private DB/path/error strings on this wire.
            let response = result.ok();
            let _ = write(&mut stream, &response).await;
        });
    }
}
async fn callback(path: &Path, service_uid: u32, authority: &Authority) -> Result<Binding> {
    protected_parent(path, service_uid)?;
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(path)).await??;
    ensure!(
        stream.peer_cred()?.uid() == service_uid,
        "Controller peer refused"
    );
    write(&mut stream, authority).await?;
    let binding: Option<Binding> = read(&mut stream).await?;
    let binding = binding.ok_or_else(|| anyhow::anyhow!("Authority refused"))?;
    ensure!(binding == authority.binding, "Authority binding refused");
    Ok(binding)
}

/// Root-owned journal; never opens the controller's database.
struct Journal {
    db: Connection,
    _lock: std::fs::File,
}
impl Journal {
    fn open(path: &Path) -> Result<Self> {
        ensure!(unsafe { libc::geteuid() } == 0, "Root journal required");
        protected_parent(path, 0)?;
        if path.exists() {
            let m = path.symlink_metadata()?;
            ensure!(
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o077 == 0,
                "Unsafe root journal"
            );
        }
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.sync_all()?;
        // Lock the private journal instance before any startup recovery writes.
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "Root journal already active"
        );
        let db = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS actor_operations(id TEXT PRIMARY KEY,binding TEXT NOT NULL,digest TEXT NOT NULL,service_uid INTEGER NOT NULL,state TEXT NOT NULL); UPDATE actor_operations SET state='uncertain' WHERE state IN ('pending','admitted');")?;
        std::fs::File::open(path.parent().unwrap())?.sync_all()?;
        Ok(Self { db, _lock: file })
    }
    fn start(&self, a: &Authority, uid: u32) -> Result<Option<Receipt>> {
        let id = scope_key(&a.binding)?;
        let hash = digest(a)?;
        let old: Option<(String, String, u32, String)> = self
            .db
            .query_row(
                "SELECT binding,digest,service_uid,state FROM actor_operations WHERE id=?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        if let Some((b, h, u, state)) = old {
            ensure!(
                h == hash && u == uid && serde_json::from_str::<Binding>(&b)? == a.binding,
                "Request binding conflict"
            );
            return Ok(Some(Receipt {
                binding: a.binding.clone(),
                service_uid: uid,
                state,
            }));
        }
        self.db.execute(
            "INSERT INTO actor_operations VALUES(?1,?2,?3,?4,'pending')",
            params![id, serde_json::to_string(&a.binding)?, hash, uid],
        )?;
        Ok(None)
    }
    fn state(&self, a: &Authority, uid: u32, state: &str) -> Result<Receipt> {
        self.db.execute(
            "UPDATE actor_operations SET state=?2 WHERE id=?1",
            params![scope_key(&a.binding)?, state],
        )?;
        Ok(Receipt {
            binding: a.binding.clone(),
            service_uid: uid,
            state: state.into(),
        })
    }
}
/// Only production dispatcher. Each adapter stays unavailable until separately qualified.
fn unavailable(_binding: &Binding) -> Result<bool> {
    Ok(false)
}
async fn execute(
    journal: &Journal,
    peer: u32,
    service_uid: u32,
    path: &Path,
    a: &Authority,
    dispatch: fn(&Binding) -> Result<bool>,
) -> Result<Receipt> {
    ensure!(peer == service_uid, "Broker peer refused");
    a.binding.request.valid()?;
    if let Some(receipt) = journal.start(a, peer)? {
        return Ok(receipt);
    }
    // Failure/timeout after durable intent is uncertain, never a license to retry.
    if callback(path, service_uid, a).await.is_err() {
        return journal.state(a, peer, "uncertain");
    }
    journal.state(a, peer, "admitted")?;
    let state = match dispatch(&a.binding) {
        Ok(true) => "completed",
        Ok(false) => "unavailable",
        Err(_) => "uncertain",
    };
    journal.state(a, peer, state)
}
/// Source substrate entry point; no CLI/installer starts this unqualified service.
pub async fn serve_root(journal_path: &Path, callback_path: &Path, service_uid: u32) -> Result<()> {
    let journal = Journal::open(journal_path)?;
    let listener = listen(Path::new(ROOT_SOCKET), 0)?;
    // Socket remains root-owned. Service UID requires separately reviewed provisioning;
    // this source does not chmod private state or install a broad transport grant.
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(cred) = stream.peer_cred() else {
            continue;
        };
        let peer = cred.uid();
        if peer != service_uid {
            continue;
        }
        let result = async {
            let a: Authority = read(&mut stream).await?;
            execute(&journal, peer, service_uid, callback_path, &a, unavailable).await
        }
        .await;
        let _ = write(&mut stream, &result.ok()).await;
    }
}
/// Called after roles::handle returns and releases Store mutex. Never exposes nonce.
pub(crate) fn dispatch_private(store: &Store, value: Value) -> Result<Value> {
    let key = value["broker_intent"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Authority unavailable"))?;
    let a = pending()
        .lock()
        .map_err(|_| anyhow::anyhow!("Authority unavailable"))?
        .remove(key)
        .ok_or_else(|| anyhow::anyhow!("Authority lost; inspect intent"))?;
    let result = (|| -> Result<Receipt> {
        use std::io::{Read, Write};
        let mut stream = connect_bounded(Path::new(ROOT_SOCKET), Duration::from_secs(2))?;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut len,
                )
            } == 0
                && cred.uid == 0,
            "Root broker peer refused"
        );
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut bytes = serde_json::to_vec(&a)?;
        bytes.push(b'\n');
        let write_result = stream.write_all(&bytes);
        use zeroize::Zeroize;
        bytes.zeroize();
        write_result?;
        let mut reader = std::io::BufReader::new(stream);
        let mut line = String::new();
        use std::io::BufRead;
        reader.by_ref().take(LIMIT + 1).read_line(&mut line)?;
        ensure!(line.len() <= LIMIT as usize, "Broker reply exceeded limits");
        let r: Receipt = serde_json::from_str::<Option<Receipt>>(&line)?
            .ok_or_else(|| anyhow::anyhow!("Broker refused"))?;
        ensure!(
            r.binding == a.binding && r.service_uid == unsafe { libc::geteuid() },
            "Root receipt binding refused"
        );
        Ok(r)
    })();
    let receipt = result.unwrap_or_else(|_| Receipt {
        binding: a.binding.clone(),
        service_uid: unsafe { libc::geteuid() },
        state: "uncertain".into(),
    });
    save_receipt(store, &receipt)?;
    Ok(serde_json::to_value(receipt)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::{Action, Envelope, Role};
    fn fixture() -> Result<(tempfile::TempDir, Store, String)> {
        let temp = tempfile::tempdir()?;
        let store = Store::open(&temp.path().join("controller"))?;
        store
            .actor_test_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        roles::init_owner(
            &store,
            unsafe { libc::geteuid() },
            crate::store::Profile::Light,
        )?;
        let token = auth::random()?;
        {
            let db = store.db()?;
            let owner: String =
                db.query_row("SELECT owner_id FROM security_config", [], |r| r.get(0))?;
            // Synthetic transport principal: no installer/OS owner alias is changed.
            db.execute(
                "INSERT INTO terminal_sessions VALUES(?1,?2,42,1,?3,?4,?3,?3)",
                params![auth::digest(&token), owner, auth::now(), auth::now() + 3600],
            )?;
        }
        Ok((temp, store, token))
    }
    fn request(id: &str, action: FixedAction) -> ReviewedRequest {
        ReviewedRequest {
            request_id: id.into(),
            product: "mail".into(),
            action,
            plan_sha256: "a".repeat(64),
        }
    }
    fn prepare(store: &Store, token: &str, request: ReviewedRequest) -> Result<Authority> {
        let e = Envelope {
            version: 1,
            request_id: request.request_id.clone(),
            session: Some(token.into()),
            confirmation: None,
            payload: Action::BrokerIntent { request },
        };
        let v = roles::handle(store, 42, &e)?;
        assert!(v.get("nonce").is_none());
        Ok(pending()
            .lock()
            .unwrap()
            .remove(v["broker_intent"].as_str().unwrap())
            .unwrap())
    }
    #[test]
    fn disabled_admission_leaves_no_intent_or_confirmation_work() -> Result<()> {
        let (_temp, store, token) = fixture()?;
        store
            .actor_test_enabled
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let request = request("disabled", FixedAction::BootSet { enabled: true });
        let e = Envelope {
            version: 1,
            request_id: "disabled".into(),
            session: Some(token),
            confirmation: Some("not-consumed".into()),
            payload: Action::BrokerIntent {
                request: request.clone(),
            },
        };
        assert_eq!(
            roles::handle(&store, 42, &e).unwrap_err().to_string(),
            "control_unavailable"
        );
        let e = Envelope {
            version: 1,
            request_id: "confirm-disabled".into(),
            session: None,
            confirmation: None,
            payload: Action::Reauthenticate {
                password: "never-hashed".into(),
                target: Box::new(Action::BrokerIntent { request }),
            },
        };
        assert_eq!(
            roles::handle(&store, 42, &e).unwrap_err().to_string(),
            "control_unavailable"
        );
        assert_eq!(
            store
                .db()?
                .query_row("SELECT COUNT(*) FROM broker_intents", [], |r| r
                    .get::<_, i64>(0))?,
            0
        );
        Ok(())
    }
    #[test]
    fn outstanding_history_caps_are_per_actor_and_preserve_uncertain() -> Result<()> {
        let (_temp, store, token) = fixture()?;
        for n in 0..4 {
            prepare(
                &store,
                &token,
                request(&format!("slot{n}"), FixedAction::Health),
            )?;
        }
        assert!(prepare(&store, &token, request("overflow", FixedAction::Health)).is_err());
        let db = store.db()?;
        let id: String = db.query_row("SELECT id FROM users", [], |r| r.get(0))?;
        db.execute("INSERT INTO users VALUES('other','other@fixture.invalid',NULL,'operator',0,0,'fixture',1)",[])?;
        let other = roles::principal(&db, "other")?;
        issue(
            &db,
            &other,
            42,
            &token,
            "other",
            &request("other", FixedAction::Health),
        )?;
        db.execute(
            "UPDATE broker_intents SET state='uncertain' WHERE json_extract(binding,'$.actor')=?1",
            [&id],
        )?;
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM broker_intents WHERE state='uncertain'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            4
        );
        assert!(
            issue(
                &db,
                &roles::principal(&db, &id)?,
                42,
                &token,
                "blocked",
                &request("blocked", FixedAction::Health)
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn retained_history_backpressure_never_prunes_security_records() -> Result<()> {
        for (rows, same_actor) in [(256, true), (4096, false)] {
            let (_temp, store, token) = fixture()?;
            let mut db = store.db()?;
            let id: String = db.query_row("SELECT id FROM users", [], |r| r.get(0))?;
            let p = roles::principal(&db, &id)?;
            let tx = db.transaction()?;
            for n in 0..rows {
                let binding =
                    json!({"actor":if same_actor{id.clone()}else{format!("other{n}")}}).to_string();
                tx.execute("INSERT INTO broker_intents VALUES(?1,?2,?1,'fixture-session','completed',NULL)",params![format!("retained{n}"),binding])?;
            }
            tx.commit()?;
            assert!(
                issue(
                    &db,
                    &p,
                    42,
                    &token,
                    "blocked",
                    &request("blocked", FixedAction::Health)
                )
                .is_err()
            );
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM broker_intents", [], |r| r
                    .get::<_, i64>(0))?,
                rows
            );
        }
        Ok(())
    }
    #[tokio::test]
    async fn callback_restart_live_socket_and_connect_bounds() -> Result<()> {
        let (_temp, store, _token) = fixture()?;
        let listener = authority_listener(&store)?;
        assert!(authority_listener(&store).is_err());
        let failure = tokio::time::timeout(
            Duration::from_millis(500),
            crate::runtime::serve(store.clone()),
        )
        .await?;
        assert!(failure.is_err());
        drop(listener);
        let listener = authority_listener(&store)?;
        let path = store.root.join("run/authority.sock");
        use std::os::fd::AsRawFd;
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let first = connect_bounded(&path, Duration::from_millis(100))?;
        let start = std::time::Instant::now();
        let mut saturated = false;
        let mut streams = vec![first];
        for _ in 0..16 {
            match connect_bounded(&path, Duration::from_millis(100)) {
                Ok(stream) => streams.push(stream),
                Err(_) => {
                    saturated = true;
                    break;
                }
            }
        }
        assert!(saturated && start.elapsed() < Duration::from_secs(1));
        let start = std::time::Instant::now();
        assert!(connect_bounded(&store.root.join("absent"), Duration::from_millis(100)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        Ok(())
    }
    #[test]
    fn root_journal_excludes_second_recovery_writer() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Exclusive root journal test requires isolated root runner");
            return Ok(());
        }
        let (temp, store, token) = fixture()?;
        let a = prepare(&store, &token, request("locked", FixedAction::Health))?;
        let path = temp.path().join("root.sqlite");
        let journal = Journal::open(&path)?;
        journal.start(&a, 0)?;
        assert!(Journal::open(&path).is_err());
        assert_eq!(
            journal
                .db
                .query_row("SELECT state FROM actor_operations", [], |r| r
                    .get::<_, String>(0))?,
            "pending"
        );
        drop(journal);
        let reopened = Journal::open(&path)?;
        assert_eq!(
            reopened
                .db
                .query_row("SELECT state FROM actor_operations", [], |r| r
                    .get::<_, String>(0))?,
            "uncertain"
        );
        Ok(())
    }
    #[test]
    fn fresh_role_matrix_and_unknown_inputs() -> Result<()> {
        let (_temp, store, token) = fixture()?;
        let db = store.db()?;
        let id: String = db.query_row(
            "SELECT user_id FROM terminal_sessions WHERE hash=?1",
            [auth::digest(&token)],
            |r| r.get(0),
        )?;
        let mut p = roles::principal(&db, &id)?;
        drop(db);
        for role in [Role::Operator, Role::Manager, Role::Viewer] {
            p.role = role;
            for level in [
                None,
                Some(roles::Level::View),
                Some(roles::Level::Operate),
                Some(roles::Level::Manage),
            ] {
                p.grants.clear();
                if let Some(l) = level {
                    p.grants.insert("mail".into(), l);
                }
                for (action, minimum) in [
                    (FixedAction::Health, roles::Level::View),
                    (FixedAction::Logs, roles::Level::Operate),
                    (FixedAction::CorePlan, roles::Level::Manage),
                    (FixedAction::BootSet { enabled: true }, roles::Level::Manage),
                ] {
                    assert_eq!(
                        roles::permits(&p, action.permission(), Some("mail")),
                        role == Role::Operator
                            || (role == Role::Manager && level.is_some_and(|l| l >= minimum))
                    );
                    assert!(!roles::permits(
                        &p,
                        action.permission(),
                        Some("/etc/passwd")
                    ));
                }
            }
        }
        assert!(serde_json::from_value::<ReviewedRequest>(json!({"request_id":"x","product":"mail","action":"health","plan_sha256":"a".repeat(64),"actor":"operator"})).is_err());
        assert!(request("x", FixedAction::BackupManage).valid().is_err());
        for field in ["unit", "actor", "command"] {
            let mut value = json!({"boot_set":{"enabled":true}});
            value["boot_set"][field] = json!("forged");
            assert!(serde_json::from_value::<FixedAction>(value).is_err());
        }
        Ok(())
    }
    #[test]
    fn real_session_role_and_grant_matrix_and_revocation() -> Result<()> {
        for role in ["operator", "manager", "viewer"] {
            for grant in [None, Some("view"), Some("operate"), Some("manage")] {
                let (_temp, store, token) = fixture()?;
                {
                    let db = store.db()?;
                    db.execute("UPDATE users SET role=?1", [role])?;
                    if let Some(grant) = grant {
                        db.execute(
                            "INSERT INTO user_grants SELECT id,'mail',?1 FROM users",
                            [grant],
                        )?;
                    }
                }
                for (name, action, manager) in [
                    ("health", FixedAction::Health, grant.is_some()),
                    (
                        "logs",
                        FixedAction::Logs,
                        matches!(grant, Some("operate" | "manage")),
                    ),
                    ("plan", FixedAction::CorePlan, grant == Some("manage")),
                ] {
                    let result = prepare(&store, &token, request(name, action));
                    let allowed = role == "operator" || (role == "manager" && manager);
                    assert_eq!(result.is_ok(), allowed, "{role} {grant:?} {name}");
                    if let Ok(a) = result {
                        admit(&store, 0, &a)?;
                    }
                }
            }
        }
        let (_temp, store, token) = fixture()?;
        {
            let db = store.db()?;
            db.execute("UPDATE users SET role='manager'", [])?;
            db.execute(
                "INSERT INTO user_grants SELECT id,'mail','view' FROM users",
                [],
            )?;
        }
        let a = prepare(&store, &token, request("grant", FixedAction::Health))?;
        store.db()?.execute("DELETE FROM user_grants", [])?;
        assert!(admit(&store, 0, &a).is_err());
        Ok(())
    }
    #[test]
    fn nonce_replay_payload_peer_and_session_refusals() -> Result<()> {
        let (_temp, store, token) = fixture()?;
        let mut a = prepare(&store, &token, request("read", FixedAction::Health))?;
        assert!(admit(&store, 42, &a).is_err());
        let plan = a.binding.request.plan_sha256.clone();
        a.binding.request.plan_sha256 = "b".repeat(64);
        assert!(admit(&store, 0, &a).is_err());
        a.binding.request.plan_sha256 = plan;
        let actor = a.binding.actor.clone();
        a.binding.actor = "forged".into();
        assert!(admit(&store, 0, &a).is_err());
        a.binding.actor = actor;
        let uid = a.binding.origin_uid;
        a.binding.origin_uid = 0;
        assert!(admit(&store, 0, &a).is_err());
        a.binding.origin_uid = uid;
        admit(&store, 0, &a)?;
        let detail: String = store.db()?.query_row(
            "SELECT detail FROM audit WHERE action='security:broker_admit' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        assert!(detail.contains("owner"));
        assert!(admit(&store, 0, &a).is_err());
        let a = prepare(&store, &token, request("revoked", FixedAction::Health))?;
        store.db()?.execute("DELETE FROM terminal_sessions", [])?;
        assert!(admit(&store, 0, &a).is_err());
        Ok(())
    }
    #[test]
    fn revisions_expiry_grants_and_restart_are_fresh() -> Result<()> {
        for change in [
            "UPDATE users SET auth_revision=auth_revision+1",
            "UPDATE security_config SET revision=revision+1",
            "UPDATE users SET disabled=1",
            "UPDATE terminal_sessions SET expires=0",
            "UPDATE terminal_sessions SET last_use=0",
            "UPDATE users SET role='viewer'",
        ] {
            let (_temp, store, token) = fixture()?;
            let a = prepare(&store, &token, request("fresh", FixedAction::Health))?;
            store.db()?.execute(change, [])?;
            assert!(admit(&store, 0, &a).is_err(), "{change}");
        }
        let (_temp, store, token) = fixture()?;
        let mut a = prepare(&store, &token, request("expired", FixedAction::Health))?;
        a.binding.expires_at = auth::now() - 1;
        store.db()?.execute(
            "UPDATE broker_intents SET binding=?1",
            [serde_json::to_string(&a.binding)?],
        )?;
        assert!(admit(&store, 0, &a).is_err());
        let a = prepare(&store, &token, request("restart", FixedAction::Health))?;
        let reopened = Store::open(&store.root)?;
        reopened
            .actor_test_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        admit(&reopened, 0, &a)?;
        assert!(admit(&Store::open(&store.root)?, 0, &a).is_err());
        Ok(())
    }
    #[test]
    fn risky_requires_confirmation_reads_do_not_and_uid_is_kernel_bound() -> Result<()> {
        let (_temp, store, token) = fixture()?;
        assert!(
            prepare(
                &store,
                &token,
                request("boot", FixedAction::BootSet { enabled: true })
            )
            .is_err()
        );
        prepare(&store, &token, request("logs", FixedAction::Logs))?;
        let req = Envelope {
            version: 1,
            request_id: "fakeuid".into(),
            session: Some(token),
            confirmation: None,
            payload: Action::BrokerIntent {
                request: request("fakeuid", FixedAction::Health),
            },
        };
        assert!(roles::handle(&store, 43, &req).is_err());
        Ok(())
    }
    #[test]
    fn exact_confirmation_binds_plan_payload_and_request_and_is_one_use() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = Store::open(&temp.path().join("protected"))?;
        store
            .actor_test_enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        store.init(
            "owner@fixture.invalid",
            "fixture-password-long",
            crate::store::Profile::Light,
            false,
        )?;
        let login = Envelope {
            version: 1,
            request_id: "login".into(),
            session: None,
            confirmation: None,
            payload: Action::Login {
                account: "owner@fixture.invalid".into(),
                password: "fixture-password-long".into(),
            },
        };
        let token = roles::handle(&store, 42, &login)?["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let target = request("exact", FixedAction::BootSet { enabled: true });
        let confirm = Envelope {
            version: 1,
            request_id: "confirm".into(),
            session: Some(token.clone()),
            confirmation: None,
            payload: Action::Reauthenticate {
                password: "fixture-password-long".into(),
                target: Box::new(Action::BrokerIntent {
                    request: target.clone(),
                }),
            },
        };
        let proof = roles::handle(&store, 42, &confirm)?["confirmation"]
            .as_str()
            .unwrap()
            .to_owned();
        for changed in [
            request("other", FixedAction::BootSet { enabled: true }),
            request("exact", FixedAction::BootSet { enabled: false }),
            ReviewedRequest {
                plan_sha256: "b".repeat(64),
                ..target.clone()
            },
        ] {
            let e = Envelope {
                version: 1,
                request_id: changed.request_id.clone(),
                session: Some(token.clone()),
                confirmation: Some(proof.clone()),
                payload: Action::BrokerIntent { request: changed },
            };
            assert!(roles::handle(&store, 42, &e).is_err());
        }
        let exact = Envelope {
            version: 1,
            request_id: "exact".into(),
            session: Some(token.clone()),
            confirmation: Some(proof),
            payload: Action::BrokerIntent { request: target },
        };
        let result = roles::handle(&store, 42, &exact)?;
        let a = pending()
            .lock()
            .unwrap()
            .remove(result["broker_intent"].as_str().unwrap())
            .unwrap();
        assert!(roles::handle(&store, 42, &exact).is_err());
        store
            .db()?
            .execute("UPDATE terminal_sessions SET authenticated_at=0", [])?;
        assert!(admit(&store, 0, &a).is_err());
        store.db()?.execute(
            "UPDATE terminal_sessions SET authenticated_at=?1",
            [auth::now()],
        )?;
        admit(&store, 0, &a)?;
        let detail:String=store.db()?.query_row("SELECT detail FROM audit WHERE action='security:broker_admit' ORDER BY id DESC LIMIT 1",[],|r|r.get(0))?;
        assert!(detail.contains("protected"));
        Ok(())
    }
    #[test]
    fn receipt_actor_product_scope_and_identical_ids_are_independent() -> Result<()> {
        let (_temp, store, token) = fixture()?;
        let a = prepare(&store, &token, request("same", FixedAction::Health))?;
        let db = store.db()?;
        let p = roles::principal(&db, &a.binding.actor)?;
        assert!(retrieve(&db, &p, "same", "mail").is_ok());
        assert!(retrieve(&db, &p, "same", "vpn").is_err());
        let mut other = p.clone();
        other.id = "other".into();
        assert!(retrieve(&db, &other, "same", "mail").is_err());
        db.execute("INSERT INTO users VALUES('other','other@fixture.invalid',NULL,'operator',0,0,'fixture',1)",[])?;
        // Same request ID owned by another resolved actor gets its own durable slot.
        issue(
            &db,
            &other,
            42,
            &token,
            "same",
            &request("same", FixedAction::Health),
        )?;
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM broker_intents", [], |r| r
                .get::<_, i64>(0))?,
            2
        );
        assert!(
            issue(
                &db,
                &p,
                42,
                &token,
                "same",
                &request("same", FixedAction::Logs)
            )
            .is_err()
        );
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_callback_concurrency_and_root_journal_no_retry() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!(
                "Root-peer/journal test requires isolated root runner; production qualification remains unavailable"
            );
            return Ok(());
        }
        let (temp, store, token) = fixture()?;
        let a = prepare(&store, &token, request("dispatch", FixedAction::Health))?;
        let task = tokio::spawn(serve_authority(store.clone()));
        let run = store.root.join("run");
        if !run.exists() {
            std::fs::create_dir(&run)?;
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = run.join("authority.sock");
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(path.exists());
        let journal = Journal::open(&temp.path().join("root.sqlite"))?;
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn dispatch(_: &Binding) -> Result<bool> {
            CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }
        let uid = unsafe { libc::geteuid() };
        assert!(
            execute(&journal, uid + 1, uid, &path, &a, dispatch)
                .await
                .is_err()
        );
        let receipt = tokio::time::timeout(
            Duration::from_secs(3),
            execute(&journal, uid, uid, &path, &a, dispatch),
        )
        .await??;
        assert_eq!(receipt.state, "completed");
        save_receipt(&store, &receipt)?;
        {
            let db = store.db()?;
            let p = roles::principal(&db, &a.binding.actor)?;
            let found = retrieve(&db, &p, "dispatch", "mail")?;
            assert_eq!(found["state"], "completed");
            assert!(found.get("nonce").is_none());
            let actor:String=db.query_row("SELECT actor FROM audit WHERE action='security:broker_result' ORDER BY id DESC LIMIT 1",[],|r|r.get(0))?;
            assert_eq!(actor, a.binding.actor);
        }
        assert_eq!(CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            execute(&journal, uid, uid, &path, &a, dispatch)
                .await?
                .state,
            "completed"
        );
        assert_eq!(CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);
        let mut forged = Authority {
            binding: a.binding.clone(),
            nonce: auth::random()?,
        };
        forged.binding.request.plan_sha256 = "b".repeat(64);
        assert!(
            execute(&journal, uid, uid, &path, &forged, dispatch)
                .await
                .is_err()
        );
        let a = prepare(&store, &token, request("uncertain", FixedAction::Health))?;
        fn fail(_: &Binding) -> Result<bool> {
            anyhow::bail!("synthetic possible side effect")
        }
        assert_eq!(
            execute(&journal, uid, uid, &path, &a, fail).await?.state,
            "uncertain"
        );
        assert_eq!(
            execute(&journal, uid, uid, &path, &a, dispatch)
                .await?
                .state,
            "uncertain"
        );
        let a = prepare(&store, &token, request("crash", FixedAction::Health))?;
        journal.start(&a, uid)?;
        drop(journal);
        let reopened = Journal::open(&temp.path().join("root.sqlite"))?;
        assert_eq!(
            execute(&reopened, uid, uid, &path, &a, dispatch)
                .await?
                .state,
            "uncertain"
        );
        task.abort();
        Ok(())
    }
}
