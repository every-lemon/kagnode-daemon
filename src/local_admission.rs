//! Disabled separate-UID transport. Policy is root controlled, never request JSON.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub const POLICY_PATH: &str = "/etc/kagnode/local-admission.json";
pub const SOCKET_DIRECTORY: &str = "/run/kagnode-control";
pub const SOCKET_PATH: &str = "/run/kagnode-control/control.sock";
/// No environment variable, JSON value or administrator setting overrides this.
pub const QUALIFIED: bool = false;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub enabled: bool,
    pub revision: u64,
    pub daemon_uid: u32,
    pub service_gid: u32,
    pub admission_gid: u32,
    pub admission_group: String,
    pub members: Vec<u32>,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.revision > 0 && self.revision <= i64::MAX as u64 && self.daemon_uid != u32::MAX,
            "Invalid admission policy"
        );
        ensure!(
            self.service_gid != u32::MAX
                && self.admission_gid != 0
                && self.admission_gid != u32::MAX
                && self.admission_gid != self.service_gid,
            "Admission group must be distinct"
        );
        ensure!(
            self.admission_group == "kagnode-terminal",
            "Unexpected admission group"
        );
        ensure!(
            self.members.len() <= 1000
                && self
                    .members
                    .iter()
                    .all(|u| *u != 0 && *u != self.daemon_uid && *u != u32::MAX),
            "Invalid admission members"
        );
        let mut members = self.members.clone();
        members.sort_unstable();
        members.dedup();
        ensure!(
            members.len() == self.members.len(),
            "Duplicate admission member"
        );
        Ok(())
    }
}
fn ancestors(path: &Path, anchor: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.starts_with(anchor),
        "Invalid trusted path"
    );
    let mut current = PathBuf::from(anchor);
    check_directory(&current, 0, None)?;
    for component in path.strip_prefix(anchor)?.components() {
        ensure!(
            matches!(component, std::path::Component::Normal(_)),
            "Invalid trusted path"
        );
        current.push(component);
        check_directory(&current, 0, None)?;
    }
    Ok(())
}
fn check_directory(path: &Path, owner: u32, gid: Option<u32>) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && !m.file_type().is_symlink() && m.uid() == owner && m.mode() & 0o022 == 0,
        "Unsafe transport directory"
    );
    if let Some(gid) = gid {
        ensure!(
            m.gid() == gid && m.mode() & 0o777 == 0o750,
            "Unexpected transport directory policy"
        );
    }
    Ok(())
}
fn read_policy(path: &Path, anchor: &Path) -> Result<Policy> {
    ancestors(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid policy path"))?,
        anchor,
    )?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o644
            && m.len() <= 16384,
        "Unsafe admission metadata"
    );
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16384, "Admission policy too large");
    let policy: Policy = serde_json::from_slice(&bytes)?;
    policy.validate()?;
    Ok(policy)
}
/// Current root-managed policy is re-opened, not cached, on each invocation.
pub fn current_policy() -> Result<Policy> {
    let p = read_policy(Path::new(POLICY_PATH), Path::new("/"))?;
    let groups = fs::read_to_string("/etc/group")?;
    let entries: Vec<_> = groups
        .lines()
        .filter_map(|l| {
            let f: Vec<_> = l.split(':').collect();
            (f.len() == 4
                && (f[0] == p.admission_group || f[2].parse::<u32>().ok() == Some(p.admission_gid)))
            .then_some(f)
        })
        .collect();
    ensure!(
        entries.len() == 1
            && entries[0][0] == p.admission_group
            && entries[0][2].parse::<u32>()? == p.admission_gid,
        "Admission group identity changed"
    );
    let accounts = fs::read_to_string("/etc/passwd")?;
    let daemon: Vec<_> = accounts
        .lines()
        .filter_map(|l| {
            let f: Vec<_> = l.split(':').collect();
            (f.len() == 7 && f[2].parse::<u32>().ok() == Some(p.daemon_uid)).then_some(f)
        })
        .collect();
    ensure!(
        daemon.len() == 1 && daemon[0][3].parse::<u32>()? == p.service_gid,
        "Daemon service identity changed"
    );
    Ok(p)
}
fn admitted(policy: &Policy, uid: u32, groups: &[u32]) -> Result<()> {
    policy.validate()?;
    ensure!(policy.enabled, "Separate-UID admission disabled");
    // Recovery and service owner are trusted deployment identities, not members.
    ensure!(
        uid == 0
            || uid == policy.daemon_uid
            || (policy.members.contains(&uid)
                && groups.contains(&policy.admission_gid)
                && !groups.contains(&policy.service_gid)),
        "Local admission refused"
    );
    Ok(())
}
/// Read the account database anew. Kernel supplementary groups on a long-lived
/// client are insufficient: removing an OS membership must revoke admission.
fn current_groups(uid: u32) -> Result<Vec<u32>> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    let mut entries = passwd.lines().filter_map(|l| {
        let f: Vec<_> = l.split(':').collect();
        (f.len() == 7 && f[2].parse::<u32>().ok() == Some(uid)).then_some(f)
    });
    let account = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("Local account unavailable"))?;
    ensure!(entries.next().is_none(), "Ambiguous local account");
    let mut groups = vec![account[3].parse()?];
    for line in fs::read_to_string("/etc/group")?.lines() {
        let f: Vec<_> = line.split(':').collect();
        if f.len() == 4 && f[3].split(',').any(|v| v == account[0]) {
            groups.push(f[2].parse()?);
        }
    }
    Ok(groups)
}
fn endpoint(policy: &Policy, socket: &Path, anchor: &Path) -> Result<()> {
    let dir = socket
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid socket path"))?;
    ancestors(
        dir.parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid socket parent"))?,
        anchor,
    )?;
    check_directory(dir, policy.daemon_uid, Some(policy.admission_gid))?;
    let m = fs::symlink_metadata(socket)?;
    ensure!(
        m.file_type().is_socket()
            && m.uid() == policy.daemon_uid
            && m.gid() == policy.admission_gid
            && m.mode() & 0o777 == 0o660,
        "Unsafe admission socket"
    );
    Ok(())
}
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(stream),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut size,
            )
        } == 0
            && size as usize == std::mem::size_of::<libc::ucred>(),
        "Peer credentials unavailable"
    );
    Ok(cred.uid)
}
fn remaining(deadline: std::time::Instant) -> Result<Duration> {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    ensure!(!left.is_zero(), "Transport deadline exceeded");
    Ok(left)
}
fn read_bounded(
    stream: &mut UnixStream,
    max: usize,
    deadline: std::time::Instant,
    newline: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let mut chunk = [0; 1024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            ensure!(!newline, "Incomplete terminal frame");
            return Ok(bytes);
        }
        ensure!(
            bytes.len() + count <= max,
            "Transport frame exceeded limits"
        );
        bytes.extend_from_slice(&chunk[..count]);
        if newline && bytes.contains(&b'\n') {
            ensure!(
                bytes.iter().position(|b| *b == b'\n') == Some(bytes.len() - 1),
                "Multiple terminal frames refused"
            );
            return Ok(bytes);
        }
    }
}
fn write_bounded(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    let mut sent = 0;
    while sent < bytes.len() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let n = stream.write(&bytes[sent..])?;
        ensure!(n > 0, "Transport closed");
        sent += n;
    }
    Ok(())
}
fn safe_error(message: &str) -> &str {
    match message {
        "Sign in again"
        | "Authentication refused"
        | "Authentication refused; retry later"
        | "Action not permitted"
        | "Fresh confirmation required"
        | "Confirmation refused"
        | "Unexpected confirmation"
        | "User changed; reload"
        | "Security settings changed; reload"
        | "Retention changed; reload"
        | "Authentication workers busy"
        | "Password workers busy; retry later"
        | "Authorization changed; retry after signing in" => message,
        _ => "Request unavailable",
    }
}
fn exchange(mut stream: UnixStream, value: &crate::roles::Envelope) -> Result<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    ensure!(bytes.len() < 16384, "Terminal request exceeded limits");
    bytes.push(b'\n');
    write_bounded(&mut stream, &bytes, deadline)?;
    let reply = read_bounded(&mut stream, 2 * 1024 * 1024, deadline, false)?;
    let response: Value = serde_json::from_slice(&reply)?;
    ensure!(
        response["ok"] == true,
        "{}",
        safe_error(response["error"].as_str().unwrap_or("Request unavailable"))
    );
    Ok(response["value"].clone())
}
/// Callable client contract for Claude. Fixed locator only; failure never retries
/// a caller-supplied endpoint. No credentials are serialized before validation.
pub fn request(value: &crate::roles::Envelope) -> Result<Value> {
    ensure!(
        QUALIFIED,
        "Separate-UID admission unavailable pending qualification"
    );
    let policy = current_policy()?;
    admitted(
        &policy,
        unsafe { libc::geteuid() },
        &current_groups(unsafe { libc::geteuid() })?,
    )?;
    exchange(
        verified_connect(&policy, Path::new(SOCKET_PATH), Path::new("/"))?,
        value,
    )
}
fn verified_connect(policy: &Policy, socket: &Path, anchor: &Path) -> Result<UnixStream> {
    endpoint(policy, socket, anchor)?;
    let stream = connect(socket)?;
    ensure!(
        peer_uid(&stream)? == policy.daemon_uid,
        "Unexpected daemon peer"
    );
    endpoint(policy, socket, anchor)?;
    Ok(stream)
}
// Nonblocking connect bounds backlog saturation as well as read/write work.
fn connect(path: &Path) -> Result<UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    ensure!(
        bytes.len() < addr.sun_path.len() && !bytes.contains(&0),
        "Invalid socket path"
    );
    addr.sun_family = libc::AF_UNIX as _;
    for (target, source) in addr.sun_path.iter_mut().zip(bytes) {
        *target = *source as _;
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    ensure!(fd >= 0, "Socket unavailable");
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let result = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&addr) as _,
        )
    };
    // AF_UNIX EAGAIN means backlog full, not an established pending connection.
    if result != 0 {
        anyhow::bail!("Daemon connection unavailable");
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}
/// Host-owner compatibility transport. It never opens Store. An admitted
/// separate UID must use the fixed locator; arbitrary roots cannot redirect it.
pub fn private_request(root: &Path, value: &crate::roles::Envelope) -> Result<Value> {
    let m = fs::symlink_metadata(root)?;
    let uid = unsafe { libc::geteuid() };
    if uid != 0 && uid != m.uid() {
        return request(value);
    }
    ensure!(
        m.is_dir() && !m.file_type().is_symlink() && m.mode() & 0o777 == 0o700,
        "Unsafe controller directory"
    );
    let run = root.join("run");
    let r = fs::symlink_metadata(&run)?;
    ensure!(
        r.is_dir()
            && !r.file_type().is_symlink()
            && r.uid() == m.uid()
            && r.mode() & 0o777 == 0o700,
        "Unsafe private socket directory"
    );
    let path = run.join("control.sock");
    let socket = fs::symlink_metadata(&path)?;
    ensure!(
        socket.file_type().is_socket() && socket.uid() == m.uid() && socket.mode() & 0o777 == 0o600,
        "Unsafe private socket"
    );
    let stream = connect(&path)?;
    ensure!(peer_uid(&stream)? == m.uid(), "Unexpected daemon peer");
    exchange(stream, value)
}
/// Exact proposed policy; rendering never mutates groups, files or services.
pub fn installer_plan(policy: &Policy) -> Result<Value> {
    policy.validate()?;
    ensure!(
        !policy.enabled,
        "Installer may only stage disabled admission"
    );
    Ok(
        serde_json::json!({"qualified":false,"apply_available":false,"policy":policy,"policy_path":POLICY_PATH,"policy_owner":"root:root","policy_mode":"0644","directory":SOCKET_DIRECTORY,"directory_uid":policy.daemon_uid,"directory_gid":policy.admission_gid,"directory_mode":"0750","socket":SOCKET_PATH,"socket_mode":"0660","controller_directory_mode":"0700","controller_file_mode":"0600","ordering":["review distinct existing service and admission IDs; refuse name/ID conflicts","create only explicitly reviewed admission group; never add service-primary-group members","provision root-owned policy parent and disabled metadata","provision service-owned 0750 public runtime directory outside controller","bind new socket exclusively; never unlink stale/live/unexpected paths","set reviewed admission group then mode0660 before accepting","qualified restart and rollback required before future enablement"],"tmpfiles_policy":format!("d {} 0750 {} {} - -",SOCKET_DIRECTORY,policy.daemon_uid,policy.admission_gid),"unit_policy":{"UMask":"0077","SupplementaryGroups":"kagnode-terminal","After":"systemd-tmpfiles-setup.service","note":"Root-reviewed tmpfiles provisioning follows group creation and precedes service startup. Do not use RuntimeDirectory: it defaults to service primary GID. Fragment is inert until full installer review."}}),
    )
}
pub fn apply_installer_plan(_plan: &Value) -> Result<()> {
    anyhow::bail!(
        "Admission installer apply unavailable pending independent review and native qualification"
    )
}

fn admission_schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS local_admission_uids(uid INTEGER PRIMARY KEY,epoch TEXT NOT NULL,revision INTEGER NOT NULL,identity TEXT NOT NULL); CREATE TABLE IF NOT EXISTS local_admission_sessions(hash TEXT PRIMARY KEY,uid INTEGER NOT NULL,epoch TEXT NOT NULL);")?;
    Ok(())
}
fn revoke_uid(db: &Connection, uid: u32) -> Result<()> {
    let actors:Vec<(String,String)>=db.prepare("SELECT DISTINCT u.id,u.email FROM terminal_sessions s JOIN users u ON u.id=s.user_id WHERE s.uid=?1 AND s.hash IN (SELECT hash FROM local_admission_sessions WHERE uid=?1)")?.query_map([uid],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<std::result::Result<_,_>>()?;
    let mode: String = db.query_row("SELECT mode FROM security_config", [], |r| r.get(0))?;
    db.execute("DELETE FROM terminal_confirmations WHERE session_hash IN (SELECT hash FROM local_admission_sessions WHERE uid=?1)",[uid])?;
    db.execute("DELETE FROM terminal_sessions WHERE uid=?1 AND hash IN (SELECT hash FROM local_admission_sessions WHERE uid=?1)",[uid])?;
    db.execute("DELETE FROM local_admission_sessions WHERE uid=?1", [uid])?;
    for (actor, account) in actors {
        db.execute("INSERT INTO audit(at,actor,action,detail) VALUES(?1,?2,'security:local_admission_revoked',?3)",params![crate::auth::now(),actor,serde_json::json!({"account":account,"uid":uid,"mode":mode,"request_id":crate::auth::random()?,"outcome":"revoked"}).to_string()])?;
    }
    Ok(())
}
fn revoke_observed(store: &crate::store::Store, uid: u32) -> Result<()> {
    // Only a previously recorded distinct admission UID may be invalidated.
    // Root/service owner traffic never creates these rows.
    if uid == 0 {
        return Ok(());
    }
    let mut db = store.db()?;
    let tx = db.transaction()?;
    admission_schema(&tx)?;
    if tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_admission_uids WHERE uid=?1)",
        [uid],
        |r| r.get::<_, bool>(0),
    )? {
        revoke_uid(&tx, uid)?;
        tx.execute(
            "UPDATE local_admission_uids SET epoch=?2,identity='revoked' WHERE uid=?1",
            params![uid, crate::auth::random()?],
        )?;
    }
    tx.commit()?;
    Ok(())
}
#[derive(PartialEq, Eq)]
struct AdmissionContext {
    uid: u32,
    epoch: Option<String>,
}
// Server-side policy, current local groups and trusted metadata fingerprint.
// Never deserialized from a client frame.
type Authorization = (Policy, Vec<u32>, String);
fn refresh_context(
    store: &crate::store::Store,
    uid: u32,
    refresh: &impl Fn(u32) -> Result<Authorization>,
) -> Result<AdmissionContext> {
    let checked = refresh(uid).and_then(|(p, g, i)| {
        admitted(&p, uid, &g)?;
        Ok((p, g, i))
    });
    let (policy, mut groups, identity) = match checked {
        Ok(v) => v,
        Err(_) => {
            revoke_observed(store, uid)?;
            anyhow::bail!("Sign in again");
        }
    };
    if uid == 0 || uid == policy.daemon_uid {
        return Ok(AdmissionContext { uid, epoch: None });
    }
    groups.sort_unstable();
    groups.dedup();
    let identity = crate::auth::digest(
        &serde_json::json!({"uid":uid,"policy":policy,"groups":groups,"local_identity":identity})
            .to_string(),
    );
    let mut db = store.db()?;
    let tx = db.transaction()?;
    admission_schema(&tx)?;
    let previous: Option<(String, i64, String)> = tx
        .query_row(
            "SELECT epoch,revision,identity FROM local_admission_uids WHERE uid=?1",
            [uid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if previous
        .as_ref()
        .is_some_and(|(_, revision, _)| (policy.revision as i64) < *revision)
    {
        revoke_uid(&tx, uid)?;
        tx.commit()?;
        anyhow::bail!("Sign in again");
    }
    let epoch = if let Some((epoch, _, old_identity)) = &previous
        && old_identity == &identity
    {
        epoch.clone()
    } else {
        revoke_uid(&tx, uid)?;
        let epoch = crate::auth::random()?;
        tx.execute("INSERT INTO local_admission_uids VALUES(?1,?2,?3,?4) ON CONFLICT(uid) DO UPDATE SET epoch=excluded.epoch,revision=excluded.revision,identity=excluded.identity",params![uid,epoch,policy.revision as i64,identity])?;
        epoch
    };
    tx.commit()?;
    Ok(AdmissionContext {
        uid,
        epoch: Some(epoch),
    })
}
fn check_bound_session(
    store: &crate::store::Store,
    context: &AdmissionContext,
    token: Option<&str>,
) -> Result<()> {
    if let (Some(epoch), Some(token)) = (&context.epoch, token) {
        ensure!(store.db()?.query_row("SELECT EXISTS(SELECT 1 FROM local_admission_sessions a JOIN terminal_sessions s ON s.hash=a.hash WHERE a.hash=?1 AND a.uid=?2 AND s.uid=?2 AND a.epoch=?3)",params![crate::auth::digest(token),context.uid,epoch],|r|r.get::<_,bool>(0))?,"Sign in again");
    }
    Ok(())
}
fn bind_issued_session(
    store: &crate::store::Store,
    context: &AdmissionContext,
    value: &Value,
) -> Result<()> {
    if let (Some(epoch), Some(token)) = (&context.epoch, value["token"].as_str()) {
        let mut db = store.db()?;
        let tx = db.transaction()?;
        if !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM local_admission_uids WHERE uid=?1 AND epoch=?2)",
            params![context.uid, epoch],
            |r| r.get::<_, bool>(0),
        )? {
            // A concurrent observed removal invalidated the login in flight.
            tx.execute(
                "DELETE FROM terminal_confirmations WHERE session_hash=?1",
                [crate::auth::digest(token)],
            )?;
            tx.execute(
                "DELETE FROM terminal_sessions WHERE hash=?1 AND uid=?2",
                params![crate::auth::digest(token), context.uid],
            )?;
            tx.commit()?;
            anyhow::bail!("Sign in again");
        }
        ensure!(
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE hash=?1 AND uid=?2)",
                params![crate::auth::digest(token), context.uid],
                |r| r.get::<_, bool>(0)
            )?,
            "Sign in again"
        );
        tx.execute("DELETE FROM local_admission_sessions WHERE hash NOT IN (SELECT hash FROM terminal_sessions)",[])?;
        tx.execute(
            "INSERT OR REPLACE INTO local_admission_sessions VALUES(?1,?2,?3)",
            params![crate::auth::digest(token), context.uid, epoch],
        )?;
        tx.commit()?;
    }
    Ok(())
}
fn admission_dispatch(
    store: &crate::store::Store,
    uid: u32,
    request: crate::roles::Envelope,
    refresh: &impl Fn(u32) -> Result<Authorization>,
) -> Result<Value> {
    let context = refresh_context(store, uid, refresh)?;
    check_bound_session(store, &context, request.session.as_deref())?;
    let result = crate::runtime::authenticated_dispatch(store, uid, request);
    if let Ok(value) = &result {
        bind_issued_session(store, &context, value)?;
    }
    let current = refresh_context(store, uid, refresh)?;
    if current != context {
        revoke_observed(store, uid)?;
        anyhow::bail!("Sign in again");
    }
    result
}
/// Normal compiled protocol implementation; fixture helpers supply policy only.
fn serve_one(
    mut stream: UnixStream,
    store: &crate::store::Store,
    refresh: impl Fn(u32) -> Result<Authorization>,
) -> Result<()> {
    let uid = peer_uid(&stream)?;
    let result = (|| -> Result<Value> {
        refresh_context(store, uid, &refresh)?;
        let line = read_bounded(
            &mut stream,
            16384,
            std::time::Instant::now() + Duration::from_secs(3),
            true,
        )?;
        let request: crate::roles::Envelope = serde_json::from_slice(&line)
            .map_err(|_| anyhow::anyhow!("Invalid terminal request"))?;
        admission_dispatch(store, uid, request, &refresh)
    })();
    let reply = match result {
        Ok(v) => serde_json::json!({"ok":true,"value":v}),
        Err(e) => serde_json::json!({"ok":false,"error":safe_error(&e.to_string())}),
    };
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&reply)?);
    ensure!(encoded.len() <= 2 * 1024 * 1024, "Response exceeded limits");
    write_bounded(
        &mut stream,
        &encoded,
        std::time::Instant::now() + Duration::from_secs(3),
    )?;
    Ok(())
}
struct StagingDirectory(PathBuf);
impl Drop for StagingDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("socket"));
        let _ = fs::remove_dir(&self.0);
    }
}
// Only a service/root-owned directory supplied internally. There is no public
// path argument and this helper never removes a destination, live or stale.
fn bind_listener(
    policy: &Policy,
    socket: &Path,
    anchor: &Path,
) -> Result<std::os::unix::net::UnixListener> {
    policy.validate()?;
    ensure!(
        policy.enabled && unsafe { libc::geteuid() } == policy.daemon_uid,
        "Daemon listener identity refused"
    );
    let dir = socket
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Invalid socket path"))?;
    ancestors(
        dir.parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid socket parent"))?,
        anchor,
    )?;
    check_directory(dir, policy.daemon_uid, Some(policy.admission_gid))?;
    // symlink_metadata detects even a dangling symlink. No probe/unlink retry.
    match fs::symlink_metadata(socket) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => anyhow::bail!("Socket path already occupied"),
    }
    let staged = dir.join(format!(".stage-{}", &crate::auth::random()?[..16]));
    fs::DirBuilder::new().mode(0o700).create(&staged)?;
    let staging = StagingDirectory(staged);
    let private = staging.0.join("socket");
    let listener = std::os::unix::net::UnixListener::bind(&private)?;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(private.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::chown(c.as_ptr(), u32::MAX, policy.admission_gid) } == 0,
        "Socket group provisioning refused"
    );
    fs::set_permissions(&private, fs::Permissions::from_mode(0o660))?;
    // Link publishes the already protected socket inode atomically, failing if
    // any actor occupied the destination. No permissive public socket window.
    fs::hard_link(&private, socket)?;
    endpoint(policy, socket, anchor)?;
    Ok(listener)
}
// Local-files identity model only: trusted inode identity and nanosecond mtime/
// ctime detect replacement and remove/readd even when final contents match.
// This deliberately expires all admitted sessions on unrelated account edits.
fn identity_metadata(paths: &[&Path]) -> Result<String> {
    let mut identities = Vec::new();
    for path in paths {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.nlink() == 1,
            "Untrusted local identity metadata"
        );
        identities.push((
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ));
    }
    Ok(crate::auth::digest(&serde_json::to_string(&identities)?))
}
fn current_authorization(uid: u32) -> Result<Authorization> {
    let paths = [
        Path::new(POLICY_PATH),
        Path::new("/etc/passwd"),
        Path::new("/etc/group"),
    ];
    let before = identity_metadata(&paths)?;
    let policy = current_policy()?;
    let groups = current_groups(uid)?;
    admitted(&policy, uid, &groups)?;
    ensure!(
        before == identity_metadata(&paths)?,
        "Local identity changed; retry"
    );
    Ok((policy, groups, before))
}
/// Fixed listener, max8 concurrent bounded connection/password workers. All
/// provisioning and OS admission remain unreachable until independent qualification.
pub fn serve(store: &crate::store::Store) -> Result<()> {
    ensure!(
        QUALIFIED,
        "Separate-UID admission unavailable pending qualification"
    );
    let policy = current_policy()?;
    let listener = bind_listener(&policy, Path::new(SOCKET_PATH), Path::new("/"))?;
    serve_listener(listener, store, current_authorization)
}
#[derive(Default)]
struct ConnectionBudget(std::sync::Mutex<std::collections::BTreeMap<u32, usize>>);
struct ConnectionPermit {
    budget: std::sync::Arc<ConnectionBudget>,
    uid: u32,
}
impl ConnectionBudget {
    fn acquire(self: &std::sync::Arc<Self>, uid: u32) -> Option<ConnectionPermit> {
        let mut counts = self.0.lock().ok()?;
        if counts.values().sum::<usize>() >= 8 || counts.get(&uid).copied().unwrap_or(0) >= 2 {
            return None;
        }
        *counts.entry(uid).or_default() += 1;
        Some(ConnectionPermit {
            budget: self.clone(),
            uid,
        })
    }
}
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.budget.0.lock()
            && let Some(n) = counts.get_mut(&self.uid)
        {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.uid);
            }
        }
    }
}
fn serve_listener(
    listener: std::os::unix::net::UnixListener,
    store: &crate::store::Store,
    refresh: fn(u32) -> Result<Authorization>,
) -> Result<()> {
    let budget = std::sync::Arc::new(ConnectionBudget::default());
    for connection in listener.incoming() {
        let stream = connection?;
        let Ok(uid) = peer_uid(&stream) else {
            continue;
        };
        let Some(permit) = budget.acquire(uid) else {
            continue;
        };
        let state = store.clone();
        std::thread::Builder::new()
            .name("kagnode-admission".into())
            .spawn(move || {
                let _permit = permit;
                let _ = serve_one(stream, &state, refresh);
            })?;
    }
    Ok(())
}
/// Fixture transport is exercised below; production does not expose a listener.
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            enabled: true,
            revision: 1,
            daemon_uid: 12345,
            service_gid: 12345,
            admission_gid: 23456,
            admission_group: "kagnode-terminal".into(),
            members: vec![34567],
        }
    }
    fn fixture_policy() -> Policy {
        let mut p = policy();
        p.daemon_uid = unsafe { libc::geteuid() };
        p
    }
    fn login_envelope() -> crate::roles::Envelope {
        serde_json::from_value(serde_json::json!({"version":1,"request_id":"admission-login","session":null,"confirmation":null,"payload":{"action":"login","account":"owner@fixture.invalid","password":"fixture-password-long"}})).unwrap()
    }
    fn whoami_envelope(token: &str) -> crate::roles::Envelope {
        crate::roles::Envelope {
            version: 1,
            request_id: "admission-whoami".into(),
            session: Some(token.into()),
            confirmation: None,
            payload: crate::roles::Action::Whoami,
        }
    }
    #[test]
    fn observed_removal_revokes_sessions_confirmations_and_allows_fresh_login() -> Result<()> {
        let t = tempfile::tempdir()?;
        let store = crate::store::Store::open(&t.path().join("controller"))?;
        store.init(
            "owner@fixture.invalid",
            "fixture-password-long",
            crate::store::Profile::Light,
            false,
        )?;
        let refresh = |_| Ok((policy(), vec![23456], "first-identity".into()));
        let before_removal = refresh_context(&store, 34567, &refresh)?;
        let login = admission_dispatch(&store, 34567, login_envelope(), &refresh)?;
        let token = login["token"].as_str().unwrap();
        admission_dispatch(&store, 34567, whoami_envelope(token), &refresh)?;
        let hash = crate::auth::digest(token);
        store.db()?.execute("INSERT INTO terminal_confirmations VALUES('fixture-confirmation',?1,1,'fixture-request',?2)",params![hash,crate::auth::now()+300])?;
        // A private-owner session with the same UID is not an admission session.
        store.db()?.execute("INSERT INTO terminal_sessions SELECT 'private-owner',user_id,uid,auth_revision,created,expires,last_use,authenticated_at FROM terminal_sessions WHERE hash=?1",[&hash])?;
        assert!(
            admission_dispatch(&store, 34567, whoami_envelope(token), &|_| Ok((
                policy(),
                vec![],
                "first-identity".into()
            )))
            .is_err()
        );
        let db = store.db()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM terminal_confirmations", [], |r| r
                .get::<_, u32>(0))?,
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM terminal_sessions WHERE hash=?1",
                [&hash],
                |r| r.get::<_, u32>(0)
            )?,
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM terminal_sessions WHERE hash='private-owner'",
                [],
                |r| r.get::<_, u32>(0)
            )?,
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM audit WHERE action='security:local_admission_revoked'",
                [],
                |r| r.get::<_, u32>(0)
            )?,
            1
        );
        drop(db);
        // Same policy revision and identity restored: deleted token stays deleted.
        assert!(admission_dispatch(&store, 34567, whoami_envelope(token), &refresh).is_err());
        assert!(before_removal != refresh_context(&store, 34567, &refresh)?);
        let fresh = admission_dispatch(&store, 34567, login_envelope(), &refresh)?;
        let token = fresh["token"].as_str().unwrap();
        admission_dispatch(&store, 34567, whoami_envelope(token), &refresh)?;
        // Quiet remove/readd between requests changes trusted filesystem metadata.
        let changed = |_| Ok((policy(), vec![23456], "second-identity".into()));
        assert!(admission_dispatch(&store, 34567, whoami_envelope(token), &changed).is_err());
        let fresh = admission_dispatch(&store, 34567, login_envelope(), &changed)?;
        admission_dispatch(
            &store,
            34567,
            whoami_envelope(fresh["token"].as_str().unwrap()),
            &changed,
        )?;
        // Persisted epoch survives a reopened Store.
        let reopened = crate::store::Store::open(&store.root)?;
        assert!(admission_dispatch(&reopened, 34567, whoami_envelope(token), &refresh).is_err());
        Ok(())
    }
    #[test]
    fn removal_during_login_does_not_leave_an_issued_session() -> Result<()> {
        let t = tempfile::tempdir()?;
        let store = crate::store::Store::open(&t.path().join("controller"))?;
        store.init(
            "owner@fixture.invalid",
            "fixture-password-long",
            crate::store::Profile::Light,
            false,
        )?;
        let calls = std::cell::Cell::new(0);
        assert!(
            admission_dispatch(&store, 34567, login_envelope(), &|_| {
                calls.set(calls.get() + 1);
                Ok((
                    policy(),
                    if calls.get() == 1 {
                        vec![23456]
                    } else {
                        vec![]
                    },
                    "fixture".into(),
                ))
            })
            .is_err()
        );
        assert_eq!(
            store
                .db()?
                .query_row("SELECT count(*) FROM terminal_sessions", [], |r| r
                    .get::<_, u32>(0))?,
            0
        );
        Ok(())
    }
    #[test]
    fn trusted_metadata_detects_same_content_rewrite_and_replacement() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        let t = tempfile::tempdir()?;
        let path = t.path().join("account-fixture");
        fs::write(&path, b"same final contents")?;
        let initial = identity_metadata(&[&path])?;
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&path, b"temporary removal")?;
        fs::write(&path, b"same final contents")?;
        let rewritten = identity_metadata(&[&path])?;
        assert_ne!(initial, rewritten);
        let replacement = t.path().join("replacement");
        fs::write(&replacement, b"same final contents")?;
        fs::rename(&replacement, &path)?;
        assert_ne!(rewritten, identity_metadata(&[&path])?);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
        assert!(identity_metadata(&[&path]).is_err());
        Ok(())
    }
    #[test]
    fn safe_auth_errors_survive_but_internal_details_are_redacted() {
        for message in [
            "Authentication refused",
            "Sign in again",
            "User changed; reload",
        ] {
            assert_eq!(safe_error(message), message);
        }
        assert_eq!(
            safe_error("database path or private implementation detail"),
            "Request unavailable"
        );
    }
    #[test]
    fn membership_never_grants_role_and_service_group_is_refused() -> Result<()> {
        let p = policy();
        admitted(&p, 34567, &[23456])?;
        assert!(admitted(&p, 34567, &[]).is_err());
        assert!(admitted(&p, 34567, &[23456, 12345]).is_err());
        assert!(admitted(&p, 45678, &[23456]).is_err());
        let mut next = p.clone();
        next.members.clear();
        next.revision += 1;
        assert!(admitted(&next, 34567, &[23456]).is_err());
        next = p.clone();
        next.enabled = false;
        assert!(admitted(&next, 0, &[]).is_err());
        admitted(&p, 0, &[])?;
        admitted(&p, p.daemon_uid, &[])?;
        Ok(())
    }
    #[test]
    fn installer_disabled_only_and_no_service_group_alias() -> Result<()> {
        let mut p = policy();
        assert!(installer_plan(&p).is_err());
        p.enabled = false;
        let plan = installer_plan(&p)?;
        assert_eq!(plan["directory_mode"], "0750");
        assert_eq!(plan["socket_mode"], "0660");
        assert!(apply_installer_plan(&plan).is_err());
        p.admission_gid = p.service_gid;
        assert!(p.validate().is_err());
        p = policy();
        p.admission_gid = u32::MAX;
        assert!(p.validate().is_err());
        p = policy();
        p.service_gid = u32::MAX;
        assert!(p.validate().is_err());
        p = policy();
        p.members.push(34567);
        assert!(p.validate().is_err());
        p = policy();
        p.admission_group = "x\nExecStart=evil".into();
        assert!(p.validate().is_err());
        Ok(())
    }
    #[test]
    fn public_gates_refuse_before_lookup() -> Result<()> {
        let request = crate::roles::Envelope {
            version: 1,
            request_id: "fixture-gate".into(),
            session: None,
            confirmation: None,
            payload: crate::roles::Action::OwnerSession,
        };
        assert!(self::request(&request).is_err());
        const {
            assert!(!QUALIFIED);
        }
        Ok(())
    }
    #[test]
    fn metadata_symlink_modes_fifo_and_endpoint_replacement() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        let t = tempfile::tempdir()?;
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700))?;
        let file = t.path().join("policy.json");
        let mut p = policy();
        p.daemon_uid = 0;
        fs::write(&file, serde_json::to_vec(&p)?)?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
        read_policy(&file, t.path())?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666))?;
        assert!(read_policy(&file, t.path()).is_err());
        fs::remove_file(&file)?;
        std::os::unix::fs::symlink("absent", &file)?;
        assert!(read_policy(&file, t.path()).is_err());
        fs::remove_file(&file)?;
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(file.as_os_str().as_bytes())?;
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert!(read_policy(&file, t.path()).is_err());
        let dir = t.path().join("runtime");
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750))?;
        p.admission_gid = fs::metadata(&dir)?.gid(); // synthetic endpoint GID, not policy validation
        let sock = dir.join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock)?;
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o660))?;
        endpoint(&p, &sock, t.path())?;
        let stream = connect(&sock)?;
        assert_eq!(peer_uid(&stream)?, 0); // actual kernel listener UID
        assert!(std::os::unix::net::UnixListener::bind(&sock).is_err());
        drop(listener);
        drop(stream);
        // A stale socket is retained; no unlink or automatic replacement.
        assert!(connect(&sock).is_err());
        assert!(sock.exists());
        fs::remove_file(&sock)?;
        fs::write(&sock, b"fake")?;
        assert!(endpoint(&p, &sock, t.path()).is_err());
        fs::remove_file(&sock)?;
        std::os::unix::fs::symlink("missing", &sock)?;
        assert!(endpoint(&p, &sock, t.path()).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770))?;
        assert!(endpoint(&p, &sock, t.path()).is_err());
        assert!(ancestors(&t.path().join("../escape"), t.path()).is_err());
        Ok(())
    }
    #[test]
    fn host_owner_backend_resolver_uses_validated_socket() -> Result<()> {
        let t = tempfile::tempdir()?;
        let store = crate::store::Store::open(&t.path().join("controller"))?;
        crate::roles::init_owner(
            &store,
            unsafe { libc::geteuid() },
            crate::store::Profile::Light,
        )?;
        let run = store.root.join("run");
        fs::create_dir(&run)?;
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700))?;
        let path = run.join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let root = store.root.clone();
        let worker = std::thread::spawn(move || -> Result<()> {
            let (stream, _) = listener.accept()?;
            serve_one(stream, &store, |_| {
                Ok((fixture_policy(), vec![], "fixture".into()))
            })
        });
        let request = crate::roles::Envelope {
            version: 1,
            request_id: "owner-client".into(),
            session: None,
            confirmation: None,
            payload: crate::roles::Action::OwnerSession,
        };
        let response = crate::runtime::authenticated_request(&root, &request)?;
        assert!(response["token"].is_string());
        worker.join().unwrap()?;
        // Unsafe socket modes are rejected before another connection attempt.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
        assert!(crate::runtime::authenticated_request(&root, &request).is_err());
        Ok(())
    }
    #[test]
    fn competing_listener_wrong_kernel_uid_gets_no_credentials() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        use std::os::unix::ffi::OsStrExt;
        let t = tempfile::tempdir()?;
        let dir = t.path().join("runtime");
        fs::create_dir(&dir)?;
        let mut p = policy();
        p.daemon_uid = 34568;
        let path = dir.join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        for target in [&dir, &path] {
            let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
            ensure!(
                unsafe { libc::chown(target.as_ptr(), p.daemon_uid, p.admission_gid) } == 0,
                "Fixture ownership failed"
            );
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660))?;
        endpoint(&p, &path, t.path())?;
        // File metadata now claims service UID34568, but listener kernel UID is0.
        assert!(verified_connect(&p, &path, t.path()).is_err());
        let (mut accepted, _) = listener.accept()?;
        accepted.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut bytes = Vec::new();
        accepted.read_to_end(&mut bytes)?;
        assert!(bytes.is_empty());
        Ok(())
    }
    #[test]
    fn actual_nobody_peer_on_owned_ephemeral_run_socket() -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;
        let t = tempfile::Builder::new()
            .prefix("kagnode-admission-fixture-")
            .tempdir_in("/run")?;
        let parent = std::ffi::CString::new(t.path().as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(parent.as_ptr(), 0, 65534) } == 0,
            "Fixture chown failed"
        );
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o750))?;
        // This root-owned fixture directory is the listener directory; anchor
        // remains /run because the helper validates real root ancestors.
        let path = t.path().join("control.sock");
        let mut p = policy();
        p.daemon_uid = 0;
        p.admission_gid = 65534;
        p.members = vec![65534];
        let listener = bind_listener(&p, &path, Path::new("/run"))?;
        let metadata = fs::metadata(&path)?;
        assert_eq!(metadata.mode() & 0o777, 0o660);
        assert_eq!(metadata.gid(), 65534);
        assert_eq!(fs::read_dir(t.path())?.count(), 1); // staging removed
        assert!(bind_listener(&p, &path, Path::new("/run")).is_err());
        listener.set_nonblocking(true)?;
        let store_dir = tempfile::tempdir()?;
        let store = crate::store::Store::open(&store_dir.path().join("controller"))?;
        crate::roles::init_owner(&store, 0, crate::store::Profile::Light)?;
        let script = r#"import socket,sys,json
s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1])
s.sendall(json.dumps({'version':1,'request_id':'nobody-owner','session':None,'confirmation':None,'payload':{'action':'owner_session'}}).encode()+b'\n')
s.shutdown(socket.SHUT_WR)
assert json.loads(s.recv(65536))['ok'] is False
"#;
        let mut child = std::process::Command::new("python3")
            .args(["-c", script])
            .arg(&path)
            .uid(65534)
            .gid(65534)
            .spawn()?;
        let until = std::time::Instant::now() + Duration::from_secs(3);
        let stream = loop {
            match listener.accept() {
                Ok((s, _)) => break Some(s),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break None,
            }
        };
        if stream.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Distinct UID fixture connection failed");
        }
        let stream = stream.unwrap();
        assert_eq!(peer_uid(&stream)?, 65534);
        // Actual client UID65534, policy/membership injection is synthetic. The
        // common compiled dispatcher refuses a non-owner passwordless session.
        let result = serve_one(stream, &store, |uid| {
            assert_eq!(uid, 65534);
            Ok((p.clone(), vec![65534], "fixture".into()))
        });
        if result.is_err() {
            let _ = child.kill();
        }
        let status = child.wait()?;
        result?;
        ensure!(status.success(), "Distinct UID fixture failed");
        drop(listener);
        assert!(bind_listener(&p, &path, Path::new("/run")).is_err()); // stale retained
        Ok(())
    }
    #[test]
    fn trickling_frames_have_absolute_deadlines_and_uid_fairness() -> Result<()> {
        let (mut client, mut server) = UnixStream::pair()?;
        let writer = std::thread::spawn(move || {
            for _ in 0..20 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        let start = std::time::Instant::now();
        assert!(read_bounded(&mut server, 16384, start + Duration::from_millis(80), true).is_err());
        assert!(start.elapsed() < Duration::from_millis(500));
        drop(server);
        writer.join().unwrap();
        let budget = std::sync::Arc::new(ConnectionBudget::default());
        let a = budget.acquire(1001).unwrap();
        let b = budget.acquire(1001).unwrap();
        assert!(budget.acquire(1001).is_none());
        let other = budget.acquire(1002).unwrap();
        drop(a);
        assert!(budget.acquire(1001).is_some());
        drop(b);
        drop(other);
        assert!(budget.0.lock().unwrap().is_empty());
        let permits: Vec<_> = (0..8)
            .map(|i| budget.acquire(2000 + i / 2).unwrap())
            .collect();
        assert!(budget.acquire(3000).is_none());
        drop(permits);
        assert!(budget.0.lock().unwrap().is_empty());
        Ok(())
    }
    #[test]
    fn malformed_and_asserted_uid_frames_are_refused() -> Result<()> {
        let t = tempfile::tempdir()?;
        let store = crate::store::Store::open(&t.path().join("controller"))?;
        for data in [
            b"{\"uid\":0}\n".to_vec(),
            vec![b'x'; 16385],
            b"{}\n{}\n".to_vec(),
        ] {
            let (mut client, server) = UnixStream::pair()?;
            client.write_all(&data)?;
            client.shutdown(std::net::Shutdown::Write)?;
            serve_one(server, &store, |_| {
                Ok((fixture_policy(), vec![], "fixture".into()))
            })?;
            let mut reply = String::new();
            client.read_to_string(&mut reply)?;
            assert_eq!(serde_json::from_str::<Value>(&reply)?["ok"], false);
        }
        Ok(())
    }
    #[test]
    fn framed_transport_kernel_peer_and_refresh_removal() -> Result<()> {
        let t = tempfile::tempdir()?;
        let store = crate::store::Store::open(&t.path().join("controller"))?;
        crate::roles::init_owner(
            &store,
            unsafe { libc::geteuid() },
            crate::store::Profile::Light,
        )?;
        let (mut client, server) = UnixStream::pair()?;
        let uid = unsafe { libc::geteuid() };
        assert_eq!(peer_uid(&server)?, uid);
        let request = crate::roles::Envelope {
            version: 1,
            request_id: "fixture-owner".into(),
            session: None,
            confirmation: None,
            payload: crate::roles::Action::OwnerSession,
        };
        let data = serde_json::to_vec(&request)?;
        client.write_all(&data)?;
        client.write_all(b"\n")?;
        let refresh = std::cell::Cell::new(0);
        serve_one(server, &store, |actual| {
            assert_eq!(actual, uid);
            refresh.set(refresh.get() + 1);
            Ok((fixture_policy(), vec![], "fixture".into()))
        })?;
        let mut reply = String::new();
        client.read_to_string(&mut reply)?;
        let reply: Value = serde_json::from_str(&reply)?;
        assert_eq!(reply["ok"], true);
        assert_eq!(refresh.get(), 3);
        let token = reply["value"]["token"].as_str().unwrap();
        let replay = crate::roles::Envelope {
            version: 1,
            request_id: "cross-uid".into(),
            session: Some(token.into()),
            confirmation: None,
            payload: crate::roles::Action::Whoami,
        };
        assert!(
            crate::runtime::authenticated_dispatch(&store, uid.wrapping_add(1), replay).is_err()
        );
        let (mut client, server) = UnixStream::pair()?;
        client.write_all(&data)?;
        client.write_all(b"\n")?;
        let calls = std::cell::Cell::new(0);
        serve_one(server, &store, |_| {
            calls.set(calls.get() + 1);
            ensure!(calls.get() < 2, "Removed member");
            Ok((fixture_policy(), vec![], "fixture".into()))
        })?;
        let mut reply = String::new();
        client.read_to_string(&mut reply)?;
        assert_eq!(serde_json::from_str::<Value>(&reply)?["ok"], false);
        assert_eq!(calls.get(), 2);
        Ok(())
    }
}
