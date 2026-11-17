//! Reviewed root-only fresh installation. Legacy adoption is a separate operation.
use crate::{
    auth,
    store::{Profile, Store},
};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

const BASE: &str = "/srv/kagnode/daemon";
const PAYLOAD: &str = "/usr/libexec/kagnode-daemon/releases";
const ENTRY: &str = "/usr/libexec/kagnode-daemon/kagnode";
const COMMAND: &str = "/usr/bin/kagnode";
const MAX_BINARY: u64 = 64 * 1024 * 1024;
const MAX_RECEIPT: u64 = 1024 * 1024;

/// Deliberately not Debug or Serialize: the password never becomes a plan/receipt.
pub enum Protection<'a> {
    Protected { account: &'a str, password: &'a str },
    Owner { actual_owner_uid: u32 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtectionChoice {
    Protected { account: String },
    Owner { actual_owner_uid: u32 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub profile: Profile,
    pub web: bool,
    pub origin: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub dev: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub version: String,
    pub options: Options,
    pub protection: ProtectionChoice,
    pub source: PathBuf,
    pub executable: Identity,
    pub source_provenance: String,
    pub service_uid: u32,
    pub service_gid: u32,
    pub units: BTreeMap<String, String>,
    pub machine_state: BTreeMap<String, String>,
    pub admin_enabled: bool,
    pub legacy_adoption: bool,
    pub plan_sha256: String,
}
fn root() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Native installation requires root"
    );
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == 0 && m.mode() & 0o022 == 0 && m.len() <= max,
        "Unsafe native installation input"
    );
    let mut bytes = Vec::new();
    (&f).take(max + 1).read_to_end(&mut bytes)?;
    let after = f.metadata()?;
    let named = path.symlink_metadata()?;
    ensure!(
        bytes.len() as u64 <= max
            && bytes.len() as u64 == m.len()
            && after.len() == m.len()
            && after.mtime_nsec() == m.mtime_nsec()
            && after.mtime() == m.mtime()
            && after.ctime_nsec() == m.ctime_nsec()
            && after.ctime() == m.ctime()
            && named.dev() == m.dev()
            && named.ino() == m.ino()
            && !named.file_type().is_symlink(),
        "Native input changed or exceeded its bound"
    );
    Ok(bytes)
}
fn protected(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir)),
        "Use fixed protected native paths"
    );
    for parent in path.ancestors() {
        let m = match parent.symlink_metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "Unsafe native installation ancestry"
        );
    }
    Ok(())
}
fn path_state(path: &Path) -> Result<String> {
    match path.symlink_metadata() {
        Ok(m) => {
            ensure!(
                !m.file_type().is_symlink(),
                "Existing symlink requires adoption review"
            );
            Ok(format!(
                "{}:{}:{}:{}:{}",
                m.dev(),
                m.ino(),
                m.uid(),
                m.mode(),
                m.len()
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("absent".into()),
        Err(e) => Err(e.into()),
    }
}
fn absent(path: &Path) -> Result<()> {
    ensure!(
        matches!(path.symlink_metadata(),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "Existing installation retained; upgrades, owner downgrade and legacy adoption require separate review"
    );
    protected(path.parent().unwrap())
}
#[derive(Clone)]
struct OsUser {
    uid: u32,
    gid: u32,
    name: String,
    home: String,
    shell: String,
}
fn user_by_uid(uid: u32) -> Result<Option<OsUser>> {
    user_lookup(None, uid)
}
fn user_by_name(name: &str) -> Result<Option<OsUser>> {
    user_lookup(Some(name), 0)
}
fn user_lookup(name: Option<&str>, uid: u32) -> Result<Option<OsUser>> {
    let mut buf = vec![0u8; 65536];
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let n = name.map(std::ffi::CString::new).transpose()?;
    let status = unsafe {
        if let Some(n) = n {
            libc::getpwnam_r(
                n.as_ptr(),
                entry.as_mut_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        } else {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        }
    };
    ensure!(status == 0, "Cannot establish local account identity");
    if result.is_null() {
        return Ok(None);
    }
    let p = unsafe { entry.assume_init() };
    let string = |p: *const libc::c_char| -> Result<String> {
        ensure!(!p.is_null(), "Incomplete local account identity");
        Ok(unsafe { std::ffi::CStr::from_ptr(p) }.to_str()?.into())
    };
    Ok(Some(OsUser {
        uid: p.pw_uid,
        gid: p.pw_gid,
        name: string(p.pw_name)?,
        home: string(p.pw_dir)?,
        shell: string(p.pw_shell)?,
    }))
}
fn group_exists(name: Option<&str>, gid: u32) -> Result<bool> {
    let mut buf = vec![0u8; 65536];
    let mut entry = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut result = std::ptr::null_mut();
    let n = name.map(std::ffi::CString::new).transpose()?;
    let status = unsafe {
        if let Some(n) = n {
            libc::getgrnam_r(
                n.as_ptr(),
                entry.as_mut_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        } else {
            libc::getgrgid_r(
                gid,
                entry.as_mut_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        }
    };
    ensure!(status == 0, "Cannot establish local group identity");
    Ok(!result.is_null())
}
/// Installer-only OS admission; no SUDO_UID/environment/session assertions.
pub(crate) fn owner_user(uid: u32) -> Result<()> {
    let u = user_by_uid(uid)?
        .ok_or_else(|| anyhow::anyhow!("Owner uid is not an existing local account"))?;
    ensure!(
        u.uid == uid
            && u.name != "kn-daemon"
            && (uid == 0
                || (uid >= 1000 && !u.shell.ends_with("nologin") && !u.shell.ends_with("false"))),
        "Owner must be the actual machine owner, not a service account"
    );
    Ok(())
}
fn normalized(choice: ProtectionChoice, options: &Options) -> Result<ProtectionChoice> {
    crate::install::plan(options.profile, options.web, &options.origin)?;
    ensure!(
        !options.origin.contains('%'),
        "Origin cannot contain systemd percent specifiers"
    );
    match choice {
        ProtectionChoice::Protected { account } => Ok(ProtectionChoice::Protected {
            account: auth::email(&account)?,
        }),
        ProtectionChoice::Owner { actual_owner_uid } => {
            ensure!(
                !options.web,
                "Unprotected owner mode requires dashboard and web administration off"
            );
            ensure!(
                actual_owner_uid == 0,
                "Native regular-owner transport is unavailable; use protected mode until owner-only socket admission is qualified"
            );
            owner_user(actual_owner_uid)?;
            Ok(ProtectionChoice::Owner { actual_owner_uid })
        }
    }
}
fn identity(path: &Path) -> Result<Identity> {
    protected(path.parent().unwrap())?;
    let bytes = read(path, MAX_BINARY)?;
    let m = path.symlink_metadata()?;
    ensure!(
        m.is_file() && m.mode() & 0o111 != 0 && bytes.len() as u64 == m.len(),
        "Native source is not a protected executable"
    );
    let machine = if cfg!(target_arch = "x86_64") {
        62
    } else if cfg!(target_arch = "aarch64") {
        183
    } else {
        bail!("Unsupported native CPU architecture")
    };
    ensure!(
        bytes.len() > 20
            && &bytes[..6] == b"\x7fELF\x02\x01"
            && u16::from_le_bytes([bytes[18], bytes[19]]) == machine,
        "Native source ELF target mismatch"
    );
    Ok(Identity {
        dev: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
        bytes: m.len(),
        sha256: digest(&bytes),
    })
}
fn payload() -> PathBuf {
    Path::new(PAYLOAD)
        .join(env!("CARGO_PKG_VERSION"))
        .join("bin/kagnode")
}
fn override_names(name: &str) -> Result<Vec<String>> {
    let (stem, kind) = name
        .rsplit_once('.')
        .ok_or_else(|| anyhow::anyhow!("Unknown fixed unit kind"))?;
    ensure!(
        matches!(kind, "service" | "timer"),
        "Unsupported fixed unit kind"
    );
    let mut names = vec![format!("{name}.d"), format!("{kind}.d")];
    for (i, c) in stem.char_indices() {
        if c == '-' {
            names.push(format!("{}.{}.d", &stem[..=i], kind));
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}
fn plan_digest(plan: &Plan) -> Result<String> {
    let mut copy = plan.clone();
    copy.plan_sha256.clear();
    Ok(digest(&serde_json::to_vec(&copy)?))
}
/// Read-only host preflight; no users, directories, lock files or units are created.
pub fn plan(options: Options, choice: ProtectionChoice) -> Result<Plan> {
    root()?;
    let protection = normalized(choice, &options)?;
    let os = read(Path::new("/etc/os-release"), 65536).or_else(|_| {
        // /etc/os-release is the standard root-owned vendor symlink on Ubuntu.
        let p = Path::new("/etc/os-release").canonicalize()?;
        protected(p.parent().unwrap())?;
        read(&p, 65536)
    })?;
    let os = std::str::from_utf8(&os)?;
    ensure!(
        (os.lines().any(|l| l == "ID=ubuntu") && os.lines().any(|l| l == "VERSION_ID=\"24.04\""))
            || (os.lines().any(|l| l == "ID=debian")
                && os.lines().any(|l| l == "VERSION_ID=\"13\"")),
        "Native setup supports Ubuntu24.04 and Debian13 only"
    );
    crate::backup_service::role::require_applications(Path::new("/srv/kagnode"))?;
    ensure!(
        user_by_name("kn-daemon")?.is_none() && !group_exists(Some("kn-daemon"), 0)?,
        "Reserved service identity already exists; review adoption/recovery"
    );
    let service_uid = (950..=999)
        .find(|id| {
            matches!(user_by_uid(*id), Ok(None)) && matches!(group_exists(None, *id), Ok(false))
        })
        .ok_or_else(|| anyhow::anyhow!("No free reviewed system service uid/gid pair"))?;
    let source = std::env::current_exe()?.canonicalize()?;
    let executable = identity(&source)?;
    let units: BTreeMap<_, _> = crate::install::units(options.profile, &options.origin)
        .into_iter()
        .map(|(name, text)| (name, text.replace("@UID@", &service_uid.to_string())))
        .collect();
    let mut machine_state = BTreeMap::new();
    for path in [
        BASE,
        ENTRY,
        COMMAND,
        "/var/lib/kagnode-daemon",
        "/etc/kagnode/daemon",
    ] {
        let p = Path::new(path);
        absent(p)?;
        machine_state.insert(path.into(), "absent".into());
    }
    for name in units.keys() {
        for dir in [
            "/etc/systemd/system",
            "/run/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ] {
            // Merged-/usr vendor unit directories may be aliases; targets remain absent.
            let dir = Path::new(dir).canonicalize()?;
            protected(&dir)?;
            let mut paths = vec![
                dir.join(name),
                dir.join("multi-user.target.wants").join(name),
                dir.join("timers.target.wants").join(name),
            ];
            paths.extend(override_names(name)?.into_iter().map(|n| dir.join(n)));
            for p in paths {
                absent(&p)?;
                machine_state.insert(p.to_string_lossy().into_owned(), "absent".into());
            }
        }
    }
    for path in [
        "/etc/passwd",
        "/etc/group",
        "/usr/sbin/groupadd",
        "/usr/sbin/useradd",
        "/usr/bin/systemctl",
    ] {
        let p = Path::new(path);
        protected(p.parent().unwrap())?;
        machine_state.insert(path.into(), digest(&read(p, MAX_BINARY)?));
    }
    for p in [
        Path::new("/srv"),
        Path::new("/srv/kagnode"),
        Path::new("/usr/libexec"),
        Path::new("/etc/systemd/system"),
    ] {
        protected(p)?;
        machine_state.insert(p.to_string_lossy().into_owned(), path_state(p)?);
    }
    let existing_payload = payload();
    protected(existing_payload.parent().unwrap())?;
    match existing_payload.symlink_metadata() {
        Ok(_) => {
            ensure!(
                identity(&existing_payload)?.sha256 == executable.sha256,
                "Existing versioned payload differs; never overwrite it"
            );
            machine_state.insert(
                existing_payload.to_string_lossy().into_owned(),
                format!("verified:{}", executable.sha256),
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            machine_state.insert(
                existing_payload.to_string_lossy().into_owned(),
                "absent".into(),
            );
        }
        Err(e) => return Err(e.into()),
    }
    let mut p=Plan{schema:1,version:env!("CARGO_PKG_VERSION").into(),options,protection,source,executable,source_provenance:"current executable bytes pinned; Git/signature provenance requires separate release verification".into(),service_uid,service_gid:service_uid,units,machine_state,admin_enabled:false,legacy_adoption:false,plan_sha256:String::new()};
    p.plan_sha256 = plan_digest(&p)?;
    Ok(p)
}
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn mkdir(path: &Path, mode: u32) -> Result<()> {
    protected(path.parent().unwrap())?;
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    sync_parent(path)
}
fn parents(path: &Path) -> Result<()> {
    if path.exists() {
        return protected(path);
    }
    if let Some(p) = path.parent() {
        parents(p)?;
    }
    mkdir(path, 0o755)
}
fn new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    parents(path.parent().unwrap())?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    sync_parent(path)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    plan_sha256: String,
    state: String,
    pending: String,
    completed: Vec<String>,
    created: BTreeMap<String, String>,
    actor: String,
    owner_uid: Option<u32>,
    service_uid: u32,
    service_gid: u32,
    error_code: Option<String>,
    reviewed_plan: Plan,
}
fn save(path: &Path, j: &Journal) -> Result<()> {
    let next = path.with_extension("next");
    new_file(&next, &serde_json::to_vec_pretty(j)?, 0o600)?;
    std::fs::rename(&next, path)?;
    sync_parent(path)
}
fn begin(path: &Path, j: &mut Journal, step: &str) -> Result<()> {
    j.pending = step.into();
    save(path, j)
}
fn complete(path: &Path, j: &mut Journal, step: &str) -> Result<()> {
    j.completed.push(step.into());
    j.pending.clear();
    save(path, j)
}
fn execute(program: &str, args: &[&str]) -> Result<()> {
    ensure!(
        matches!(
            program,
            "/usr/sbin/groupadd" | "/usr/sbin/useradd" | "/usr/bin/systemctl"
        ),
        "Unreviewed native executable"
    );
    let mut command = Command::new(program);
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0
                || libc::syscall(
                    libc::SYS_close_range,
                    3u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let start = std::time::Instant::now();
    loop {
        if let Some(s) = child.try_wait()? {
            ensure!(
                s.success(),
                "Fixed native operation failed; inspect recovery receipt"
            );
            return Ok(());
        }
        if start.elapsed() > std::time::Duration::from_secs(30) {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            bail!("Native operation timed out; outcome requires recovery inspection")
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}
fn assign_state(state: &Path, uid: u32, gid: u32) -> Result<()> {
    for path in std::fs::read_dir(state)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?
    {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file() && m.nlink() == 1 && m.uid() == 0,
            "Unexpected new controller-state entry"
        );
        ensure!(
            unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&f), uid, gid) } == 0,
            "Cannot assign private controller file"
        );
        f.sync_all()?;
    }
    let directory = File::open(state)?;
    ensure!(
        unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&directory), uid, gid) } == 0,
        "Cannot assign controller directory"
    );
    directory.sync_all()?;
    Ok(())
}
/// Apply only an unchanged root-reviewed fresh plan. No ordinary socket caller can invoke this API.
pub fn apply_reviewed(
    reviewed: &Plan,
    protection: Protection<'_>,
    expected_plan_sha256: &str,
) -> Result<serde_json::Value> {
    root()?;
    ensure!(
        reviewed.schema == 1
            && !reviewed.admin_enabled
            && !reviewed.legacy_adoption
            && plan_digest(reviewed)? == expected_plan_sha256
            && reviewed.plan_sha256 == expected_plan_sha256,
        "Native installation plan hash mismatch"
    );
    let (choice, prepared) = match protection {
        Protection::Protected { account, password } => {
            let account = auth::email(account)?;
            let hash = Zeroizing::new(auth::hash_password(password)?);
            (ProtectionChoice::Protected { account }, Some(hash))
        }
        Protection::Owner { actual_owner_uid } => {
            (ProtectionChoice::Owner { actual_owner_uid }, None)
        }
    };
    ensure!(
        choice == reviewed.protection,
        "Installation identity differs from reviewed plan"
    );
    let fresh = plan(reviewed.options.clone(), choice.clone())?;
    ensure!(
        fresh == *reviewed,
        "Native installation state changed; review a new plan"
    );
    let _role = crate::backup_service::role::Guard::acquire(Path::new("/srv/kagnode"))?;
    crate::backup_service::role::require_applications(Path::new("/srv/kagnode"))?;
    // Password, account, executable and every conflict were checked before any account/service creation.
    for p in [
        BASE,
        ENTRY,
        COMMAND,
        "/var/lib/kagnode-daemon",
        "/etc/kagnode/daemon",
    ] {
        absent(Path::new(p))?;
    }
    let base = Path::new(BASE);
    mkdir(base, 0o755)?;
    let record = base.join("installation.json");
    let owner_uid = match choice {
        ProtectionChoice::Owner { actual_owner_uid } => Some(actual_owner_uid),
        _ => None,
    };
    let actor = match &choice {
        ProtectionChoice::Protected { account } => account.clone(),
        ProtectionChoice::Owner { actual_owner_uid } => {
            format!("machine-owner-uid:{actual_owner_uid}")
        }
    };
    let mut j = Journal {
        schema: 1,
        plan_sha256: reviewed.plan_sha256.clone(),
        state: "preparing".into(),
        pending: String::new(),
        completed: vec![],
        created: BTreeMap::new(),
        actor,
        owner_uid,
        service_uid: reviewed.service_uid,
        service_gid: reviewed.service_gid,
        error_code: None,
        reviewed_plan: reviewed.clone(),
    };
    save(&record, &j)?;
    let result = (|| -> Result<()> {
        begin(&record, &mut j, "initialize-private-state")?;
        let state = base.join("controller");
        let store = Store::open(&state)?;
        match &choice {
            ProtectionChoice::Protected { account } => store.init_prepared(
                account,
                prepared.as_ref().unwrap(),
                reviewed.options.profile,
                reviewed.options.web,
            )?,
            ProtectionChoice::Owner { actual_owner_uid } => crate::roles::init_owner_for_installer(
                &store,
                *actual_owner_uid,
                reviewed.options.profile,
            )?,
        };
        ensure!(
            !store.db()?.query_row(
                "SELECT admin_enabled FROM security_config WHERE id=1",
                [],
                |r| r.get::<_, bool>(0)
            )?,
            "Fresh web administration must default off"
        );
        drop(store);
        j.created.insert(
            state.to_string_lossy().into_owned(),
            "new private controller directory; data retained on failure".into(),
        );
        complete(&record, &mut j, "initialize-private-state")?;
        begin(&record, &mut j, "create-service-group")?;
        let gid = reviewed.service_gid.to_string();
        execute(
            "/usr/sbin/groupadd",
            &["--system", "--gid", &gid, "kn-daemon"],
        )?;
        complete(&record, &mut j, "create-service-group")?;
        begin(&record, &mut j, "create-service-user")?;
        let uid = reviewed.service_uid.to_string();
        execute(
            "/usr/sbin/useradd",
            &[
                "--system",
                "--uid",
                &uid,
                "--gid",
                &gid,
                "--home-dir",
                "/srv/kagnode/daemon/controller",
                "--no-create-home",
                "--no-log-init",
                "--shell",
                "/usr/sbin/nologin",
                "kn-daemon",
            ],
        )?;
        let user = user_by_name("kn-daemon")?
            .ok_or_else(|| anyhow::anyhow!("Service identity absent after creation"))?;
        ensure!(
            user.uid == reviewed.service_uid
                && user.gid == reviewed.service_gid
                && user.home == "/srv/kagnode/daemon/controller"
                && user.shell == "/usr/sbin/nologin"
                && owner_uid != Some(user.uid),
            "Created service identity differs from reviewed plan"
        );
        complete(&record, &mut j, "create-service-user")?;
        begin(&record, &mut j, "private-state-ownership")?;
        assign_state(&state, user.uid, user.gid)?;
        for p in ["/var/lib/kagnode-daemon", "/etc/kagnode/daemon"] {
            mkdir(Path::new(p), 0o700)?;
        }
        complete(&record, &mut j, "private-state-ownership")?;
        begin(&record, &mut j, "install-pinned-payload")?;
        let bytes = read(&reviewed.source, MAX_BINARY)?;
        ensure!(
            digest(&bytes) == reviewed.executable.sha256,
            "Executable changed before staging"
        );
        let payload = payload();
        if !payload.exists() {
            new_file(&payload, &bytes, 0o755)?;
            j.created
                .insert(payload.to_string_lossy().into_owned(), digest(&bytes));
        } else {
            ensure!(
                identity(&payload)?.sha256 == reviewed.executable.sha256,
                "Versioned payload changed"
            );
        }
        std::os::unix::fs::symlink(&payload, ENTRY)?;
        sync_parent(Path::new(ENTRY))?;
        std::os::unix::fs::symlink(ENTRY, COMMAND)?;
        sync_parent(Path::new(COMMAND))?;
        j.created
            .insert(ENTRY.into(), format!("symlink:{}", payload.display()));
        j.created.insert(COMMAND.into(), format!("symlink:{ENTRY}"));
        complete(&record, &mut j, "install-pinned-payload")?;
        begin(&record, &mut j, "install-fixed-units")?;
        for (name, text) in &reviewed.units {
            let path = Path::new("/etc/systemd/system").join(name);
            new_file(&path, text.as_bytes(), 0o644)?;
            j.created
                .insert(path.to_string_lossy().into_owned(), digest(text.as_bytes()));
            save(&record, &j)?;
        }
        complete(&record, &mut j, "install-fixed-units")?;
        begin(&record, &mut j, "activate-new-services")?;
        execute("/usr/bin/systemctl", &["daemon-reload"])?;
        execute(
            "/usr/bin/systemctl",
            &[
                "enable",
                "--now",
                "kagnode-daemon-broker.service",
                "kagnode-daemon.service",
            ],
        )?;
        if reviewed.options.profile == Profile::Production {
            execute(
                "/usr/bin/systemctl",
                &[
                    "enable",
                    "--now",
                    "kagnode-daemon-monitor.timer",
                    "kagnode-daemon-backup.timer",
                ],
            )?;
        }
        execute(
            "/usr/bin/systemctl",
            &[
                "is-active",
                "--quiet",
                "kagnode-daemon-broker.service",
                "kagnode-daemon.service",
            ],
        )?;
        complete(&record, &mut j, "activate-new-services")?;
        j.state = "started".into();
        save(&record, &j)?;
        Ok(())
    })();
    if result.is_err() {
        j.state = "needs_recovery".into();
        j.error_code = Some("native_step_failed_or_uncertain".into());
        let _ = save(&record, &j);
    }
    result?;
    Ok(
        serde_json::json!({"state":j.state,"plan_sha256":j.plan_sha256,"protection":reviewed.protection,"admin_enabled":false,"uid":j.service_uid,"gid":j.service_gid,"binary_sha256":reviewed.executable.sha256,"terminal_integration":"requires independent real-owner/service-uid qualification","native_qualification":false}),
    )
}
/// Root-private, bounded approval document; secret input is separate.
pub fn read_plan(path: &Path) -> Result<Plan> {
    root()?;
    let m = path.symlink_metadata()?;
    ensure!(
        m.mode() & 0o077 == 0,
        "Reviewed native plan file must be private"
    );
    Ok(serde_json::from_slice(&read(path, MAX_RECEIPT)?)?)
}
/// Inspection only: never blindly repeat a timed-out user/service operation or delete state.
pub fn recovery_status() -> Result<serde_json::Value> {
    root()?;
    let path = Path::new(BASE).join("installation.json");
    let bytes = read(&path, MAX_RECEIPT)?;
    let j: Journal = serde_json::from_slice(&bytes)?;
    ensure!(j.schema == 1, "Unknown native installation receipt");
    Ok(
        serde_json::json!({"state":j.state,"pending":j.pending,"completed":j.completed,"created":j.created,"plan_sha256":j.plan_sha256,"automatic_retry":false,"rollback":"separate reviewed inspection required; controller data and identities retained"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options() -> Options {
        Options {
            profile: Profile::Light,
            web: false,
            origin: "http://127.0.0.1:8750".into(),
        }
    }
    fn fixture_plan() -> Plan {
        let mut p = Plan {
            schema: 1,
            version: "5.0.3".into(),
            options: options(),
            protection: ProtectionChoice::Owner {
                actual_owner_uid: 0,
            },
            source: "/fixture/verified-kagnode".into(),
            executable: Identity {
                dev: 1,
                inode: 2,
                uid: 0,
                mode: 0o100755,
                bytes: 12,
                sha256: "a".repeat(64),
            },
            source_provenance: "fixture only".into(),
            service_uid: 950,
            service_gid: 950,
            units: BTreeMap::from([("kagnode-daemon.service".into(), "fixture".into())]),
            machine_state: BTreeMap::from([("/fixture/target".into(), "absent".into())]),
            admin_enabled: false,
            legacy_adoption: false,
            plan_sha256: String::new(),
        };
        p.plan_sha256 = plan_digest(&p).unwrap();
        p
    }
    #[test]
    fn all_applicable_unit_dropin_levels_are_audited() -> Result<()> {
        let names = override_names("kagnode-daemon-broker.service")?;
        for expected in [
            "service.d",
            "kagnode-.service.d",
            "kagnode-daemon-.service.d",
            "kagnode-daemon-broker.service.d",
        ] {
            assert!(names.iter().any(|n| n == expected));
        }
        assert!(override_names("not-a-unit").is_err());
        Ok(())
    }
    #[test]
    fn root_only_api_refuses_a_changed_plan_before_mutation() -> Result<()> {
        let p = fixture_plan();
        assert!(
            apply_reviewed(
                &p,
                Protection::Owner {
                    actual_owner_uid: 0
                },
                &"b".repeat(64)
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn plan_hash_binds_identity_modes_units_and_host_state() -> Result<()> {
        let p = fixture_plan();
        assert_eq!(p.plan_sha256, plan_digest(&p)?);
        for n in 0..9 {
            let mut changed = p.clone();
            match n {
                0 => changed.options.web = true,
                1 => {
                    changed.protection = ProtectionChoice::Owner {
                        actual_owner_uid: 1000,
                    }
                }
                2 => {
                    changed.protection = ProtectionChoice::Protected {
                        account: "operator@fixture.invalid".into(),
                    }
                }
                3 => changed.executable.sha256 = "b".repeat(64),
                4 => changed.executable.inode += 1,
                5 => changed.service_uid += 1,
                6 => {
                    changed
                        .units
                        .insert("kagnode-daemon.service".into(), "different".into());
                }
                7 => {
                    changed
                        .machine_state
                        .insert("/fixture/target".into(), "exists".into());
                }
                _ => changed.admin_enabled = true,
            }
            assert_ne!(p.plan_sha256, plan_digest(&changed)?);
        }
        Ok(())
    }
    #[test]
    fn owner_mode_cannot_enable_dashboard_or_accept_service_accounts() -> Result<()> {
        let mut o = options();
        o.web = true;
        assert!(
            normalized(
                ProtectionChoice::Owner {
                    actual_owner_uid: 0
                },
                &o
            )
            .is_err()
        );
        assert!(
            normalized(
                ProtectionChoice::Owner {
                    actual_owner_uid: 2000
                },
                &options()
            )
            .unwrap_err()
            .to_string()
            .contains("transport is unavailable")
        );
        assert!(owner_user(u32::MAX).is_err());
        assert!(owner_user(65534).is_err());
        if unsafe { libc::geteuid() } == 0 {
            owner_user(0)?;
        }
        Ok(())
    }
    #[test]
    fn origin_injection_and_systemd_specifiers_are_refused() -> Result<()> {
        for origin in [
            "https://example.invalid/\nExecStart=bad",
            "https://example.invalid/path",
            "https://user:password@example.invalid",
            "https://example.invalid?x=1",
            "https://example.invalid#fragment",
            "https://%65xample.invalid",
            "https://example.invalid\\",
            "https://$home.invalid",
            "https://example.invalid\"",
        ] {
            let mut o = options();
            o.origin = origin.into();
            assert!(
                normalized(
                    ProtectionChoice::Protected {
                        account: "owner@fixture.invalid".into()
                    },
                    &o
                )
                .is_err(),
                "{origin}"
            );
        }
        assert_eq!(
            normalized(
                ProtectionChoice::Protected {
                    account: " OWNER@FIXTURE.INVALID ".into()
                },
                &options()
            )?,
            ProtectionChoice::Protected {
                account: "owner@fixture.invalid".into()
            }
        );
        Ok(())
    }
    #[test]
    fn no_existing_target_or_dangling_ancestor_can_be_adopted() -> Result<()> {
        let t = tempfile::tempdir()?;
        let p = t.path().join("state");
        std::fs::write(&p, b"retained")?;
        assert!(absent(&p).is_err());
        std::os::unix::fs::symlink(t.path().join("missing"), t.path().join("dangling"))?;
        assert!(protected(&t.path().join("dangling/child")).is_err());
        assert_eq!(std::fs::read(p)?, b"retained");
        Ok(())
    }
    #[test]
    fn unsafe_file_inputs_include_fifos_links_and_hardlinks() -> Result<()> {
        let t = tempfile::tempdir()?;
        let original = t.path().join("original");
        std::fs::write(&original, b"fixture")?;
        std::fs::hard_link(&original, t.path().join("hard"))?;
        assert!(read(&original, MAX_RECEIPT).is_err());
        std::os::unix::fs::symlink(&original, t.path().join("symlink"))?;
        assert!(read(&t.path().join("symlink"), MAX_RECEIPT).is_err());
        let fifo = t.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())?;
        ensure!(
            unsafe { libc::mkfifo(name.as_ptr(), 0o600) } == 0,
            "fixture fifo"
        );
        let start = std::time::Instant::now();
        assert!(read(&fifo, MAX_RECEIPT).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        Ok(())
    }
    #[test]
    fn prepared_password_and_owner_initialization_retain_admin_off_and_no_reset() -> Result<()> {
        let t = tempfile::tempdir()?;
        let protected = Store::open(&t.path().join("protected"))?;
        let hash = auth::hash_password("synthetic-password-long")?;
        protected.init_prepared("owner@fixture.invalid", &hash, Profile::Light, true)?;
        assert!(protected.require_web_admin().is_err());
        assert!(
            protected
                .init_prepared("other@fixture.invalid", &hash, Profile::Light, false)
                .is_err()
        );
        let owner = Store::open(&t.path().join("owner"))?;
        if unsafe { libc::geteuid() } == 0 {
            crate::roles::init_owner_for_installer(&owner, 0, Profile::Light)?;
            assert!(!owner.settings()?.web_enabled);
            let db = owner.db()?;
            assert_eq!(
                db.query_row("SELECT owner_uid FROM security_config", [], |r| r
                    .get::<_, u32>(0))?,
                0
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM users WHERE role='operator'",
                    [],
                    |r| r.get::<_, u32>(0)
                )?,
                1
            );
            drop(db);
            assert!(crate::roles::init_owner_for_installer(&owner, 0, Profile::Light).is_err());
        } else {
            assert!(crate::roles::init_owner_for_installer(&owner, 0, Profile::Light).is_err());
        }
        assert!(
            crate::roles::init_owner(
                &owner,
                unsafe { libc::geteuid() }.saturating_add(1),
                Profile::Light
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn journal_records_pending_step_before_uncertain_failure() -> Result<()> {
        // Root ownership is deliberately required by the real journal writer.
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        // The real journal requires protected ancestry; /tmp is deliberately rejected.
        // Keep this synthetic fixture in the root-owned checkout, never weaken that check.
        let t = tempfile::tempdir_in(std::env::current_dir()?)?;
        let record = t.path().join("installation.json");
        let p = fixture_plan();
        let mut j = Journal {
            schema: 1,
            plan_sha256: p.plan_sha256.clone(),
            state: "preparing".into(),
            pending: String::new(),
            completed: vec![],
            created: BTreeMap::new(),
            actor: "fixture".into(),
            owner_uid: Some(0),
            service_uid: 950,
            service_gid: 950,
            error_code: None,
            reviewed_plan: p,
        };
        save(&record, &j)?;
        begin(&record, &mut j, "create-service-user")?;
        j.state = "needs_recovery".into();
        j.error_code = Some("fixture_uncertain".into());
        save(&record, &j)?;
        let saved: Journal = serde_json::from_slice(&read(&record, MAX_RECEIPT)?)?;
        assert_eq!(saved.pending, "create-service-user");
        assert!(saved.completed.is_empty());
        assert_eq!(saved.state, "needs_recovery");
        assert_eq!(record.metadata()?.mode() & 0o077, 0);
        assert!(
            !String::from_utf8(read(&record, MAX_RECEIPT)?)?.contains("synthetic-password-long")
        );
        Ok(())
    }
}
