//! Reviewed exclusive-role reservation shared by native and compatibility installers.
//! Reservation is not service activation or native qualification.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
const MARKER: &str = ".kagnode-role.json";
pub struct Guard {
    _file: fs::File,
}
impl Guard {
    pub fn acquire(root: &Path) -> Result<Self> {
        ensure!(root.is_absolute(), "Use an absolute managed root");
        for p in root.ancestors().filter(|p| p.exists()) {
            let m = p.symlink_metadata()?;
            ensure!(
                m.is_dir()
                    && !m.file_type().is_symlink()
                    && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                    && (m.mode() & 0o022 == 0
                        || (p == Path::new("/tmp") && m.mode() & 0o1000 != 0)),
                "Unsafe managed root"
            );
        }
        fs::create_dir_all(root)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join(".kagnode-role.lock"))?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.mode() & 0o077 == 0
                && m.uid() == unsafe { libc::geteuid() },
            "Unsafe role lock"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "Another installer is reviewing/changing this root"
        );
        Ok(Self { _file: file })
    }
}
pub fn require_applications(root: &Path) -> Result<()> {
    // Any marker (even corrupt or symlinked) fails closed. Only an explicit
    // reviewed decommission may clear a reservation; never remove it on failure.
    for p in [
        root.join(MARKER),
        root.join("backup-server"),
        root.join("daemon/controller/backup-server.json"),
        root.join("controller/backup-server.json"),
    ] {
        ensure!(
            matches!(p.symlink_metadata(),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
            "Backup Server reservation/configuration blocks application installation"
        );
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub root: PathBuf,
    pub role: String,
    pub inventory: Vec<String>,
    pub sha256: String,
}
fn inventory(root: &Path) -> Result<Vec<String>> {
    super::supervisor::require_exclusive(root)?;
    let mut result = Vec::new();
    for e in fs::read_dir(root)? {
        let e = e?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Non-UTF8 managed path"))?;
        if name == ".kagnode-role.lock" {
            continue;
        }
        ensure!(
            name != ".kagnode-role.json" && name != "backup-server",
            "Role is already reserved; inspect receipt"
        );
        ensure!(
            matches!(name.as_str(), "daemon" | "controller" | "core"),
            "Unrecognized files need review before reserving Backup Server"
        );
        let m = e.path().symlink_metadata()?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink() && m.mode() & 0o022 == 0,
            "Unsafe managed directory"
        );
        // Bind top-level installation identities; the exclusive audit is repeated
        // at apply under the same shared installer lock.
        result.push(format!(
            "{name}:{}:{}:{}:{}",
            m.dev(),
            m.ino(),
            m.uid(),
            m.mode()
        ));
    }
    result.sort();
    Ok(result)
}
fn build(root: &Path) -> Result<Plan> {
    let mut p = Plan {
        schema: 1,
        root: root.to_owned(),
        role: "backup-server".into(),
        inventory: inventory(root)?,
        sha256: String::new(),
    };
    p.sha256 = crate::auth::digest(&serde_json::to_string(&p)?);
    Ok(p)
}
pub fn plan(root: &Path) -> Result<Plan> {
    let _guard = Guard::acquire(root)?;
    build(root)
}
pub fn apply(root: &Path, reviewed: &Plan) -> Result<Value> {
    let _guard = Guard::acquire(root)?;
    let receipt = root.join(MARKER);
    if receipt.try_exists()? {
        let value: Value = serde_json::from_slice(&super::transport::read_file(&receipt, true)?)?;
        ensure!(
            value["plan_sha256"] == reviewed.sha256 && reviewed.root == root,
            "Different existing role reservation"
        );
        return Ok(value);
    }
    let current = build(root)?;
    ensure!(
        serde_json::to_value(&current)? == serde_json::to_value(reviewed)?,
        "Role plan changed; inspect a fresh plan"
    );
    let value = json!({"schema":1,"role":"backup-server","state":"reserved","plan_sha256":current.sha256,"root":root,"reserved_at":crate::auth::now(),"activation":"separate-user service installation and qualification required"});
    let tmp = root.join(format!(".role-{}.tmp", crate::auth::random()?));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    f.write_all(&serde_json::to_vec(&value)?)?;
    f.sync_all()?;
    fs::rename(&tmp, &receipt)?;
    fs::File::open(root)?.sync_all()?;
    fs::set_permissions(receipt, fs::Permissions::from_mode(0o600))?;
    Ok(value)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub root: PathBuf,
    pub config_source: PathBuf,
    pub worker_binary: PathBuf,
    pub unit_directory: PathBuf,
    pub controller_config: PathBuf,
    pub worker_uid: u32,
    pub controller_gid: u32,
    pub config: super::transport::Config,
    pub inputs: std::collections::BTreeMap<String, String>,
    pub unit: String,
    pub sha256: String,
}
fn account_gid(uid: u32) -> Result<u32> {
    // Reentrant lookup; neither allocates users nor changes group membership.
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    ensure!(
        unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        } == 0
            && !result.is_null(),
        "Create/review the dedicated service account before installation"
    );
    Ok(unsafe { entry.assume_init() }.pw_gid)
}
fn protected_file_hash(path: &Path, owners: &[u32], secret: bool) -> Result<String> {
    use std::io::Read;
    ensure!(
        path.is_absolute()
            && path
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)),
        "Service paths must be absolute and contain no unit syntax"
    );
    for p in path.ancestors().skip(1) {
        let m = p.symlink_metadata()?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && (m.uid() == 0 || owners.contains(&m.uid()))
                && (m.mode() & 0o022 == 0 || (p == Path::new("/tmp") && m.mode() & 0o1000 != 0)),
            "Unsafe service path ancestor"
        );
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && owners.contains(&m.uid())
            && m.mode() & 0o022 == 0
            && (!secret || m.mode() & 0o077 == 0)
            && m.len() <= 256 * 1024 * 1024,
        "Unsafe service input"
    );
    let mut reader = f.take(256 * 1024 * 1024 + 1);
    let mut hasher = sha2::Sha256::default();
    use sha2::Digest;
    let mut buf = [0; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
fn build_install(
    root: &Path,
    source: &Path,
    binary: &Path,
    unit_directory: &Path,
    controller_config: &Path,
) -> Result<Installation> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Service installation requires root"
    );
    let reservation: Value =
        serde_json::from_slice(&super::transport::read_file(&root.join(MARKER), true)?)?;
    ensure!(
        reservation["role"] == "backup-server" && reservation["state"] == "reserved",
        "Review and reserve the Backup Server role first"
    );
    super::supervisor::require_exclusive(root)?;
    let config = super::transport::Config::load(source)?;
    let worker = config.repository.symlink_metadata()?;
    let controller_uid = config
        .controller_uid
        .ok_or_else(|| anyhow::anyhow!("Controller UID required"))?;
    ensure!(
        worker.is_dir()
            && !worker.file_type().is_symlink()
            && worker.mode() & 0o077 == 0
            && worker.uid() != 0
            && controller_uid != 0
            && worker.uid() != controller_uid,
        "Use a separate non-root private worker repository"
    );
    let controller_dir = controller_config
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing controller directory"))?;
    ensure!(
        controller_dir.symlink_metadata()?.uid() == controller_uid
            && controller_dir.symlink_metadata()?.mode() & 0o077 == 0
            && controller_config
                .file_name()
                .is_some_and(|f| f == "backup-server.json"),
        "Controller configuration path/owner mismatch"
    );
    ensure!(
        !config.repository.starts_with(controller_dir)
            && !controller_dir.starts_with(&config.repository),
        "Controller and repository must be disjoint"
    );
    ensure!(
        config.control_socket == Path::new("/run/kagnode-backup/admin.sock"),
        "Use the dedicated control socket"
    );
    let controller_gid = account_gid(controller_uid)?;
    ensure!(controller_gid != 0, "Controller IPC group must not be root");
    account_gid(worker.uid())?;
    let mut inputs = std::collections::BTreeMap::new();
    for (p, secret, owners) in [
        (source, true, vec![0]),
        (binary, false, vec![0]),
        (config.certificate.as_path(), false, vec![0, worker.uid()]),
        (config.private_key.as_path(), true, vec![worker.uid()]),
        (config.client_ca.as_path(), false, vec![0, worker.uid()]),
    ] {
        inputs.insert(
            p.to_string_lossy().into_owned(),
            protected_file_hash(p, &owners, secret)?,
        );
    }
    let private_key = zeroize::Zeroizing::new(fs::read(&config.private_key)?);
    super::transport::tls_material(
        &fs::read(&config.client_ca)?,
        &fs::read(&config.certificate)?,
        &private_key,
    )?;
    ensure!(
        binary.symlink_metadata()?.mode() & 0o111 != 0,
        "Worker binary is not executable"
    );
    // Fixed operations only. Installation leaves the unit disabled; activation
    // follows disposable native qualification and an owner's explicit action.
    let service_config = root.join("backup-server/config.json");
    for path in [root, unit_directory] {
        validate_unit_path(path)?;
    }
    let unit = service_unit(
        worker.uid(),
        controller_gid,
        binary,
        &service_config,
        &config.repository,
        controller_dir,
    )?;
    let mut plan = Installation {
        root: root.into(),
        config_source: source.into(),
        worker_binary: binary.into(),
        unit_directory: unit_directory.into(),
        controller_config: controller_config.into(),
        worker_uid: worker.uid(),
        controller_gid,
        config,
        inputs,
        unit,
        sha256: String::new(),
    };
    plan.sha256 = crate::auth::digest(&serde_json::to_string(&plan)?);
    Ok(plan)
}
pub fn installation_plan(
    root: &Path,
    source: &Path,
    binary: &Path,
    unit_directory: &Path,
    controller_config: &Path,
) -> Result<Installation> {
    let _guard = Guard::acquire(root)?;
    build_install(root, source, binary, unit_directory, controller_config)
}
fn create_owned(path: &Path, bytes: &[u8], mode: u32, uid: u32, gid: u32) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)?;
    f.write_all(bytes)?;
    ensure!(
        unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } == 0,
        "Cannot assign installed file owner"
    );
    f.sync_all()?;
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
pub fn install(plan: &Installation) -> Result<Value> {
    let _guard = Guard::acquire(&plan.root)?;
    let rebuilt = build_install(
        &plan.root,
        &plan.config_source,
        &plan.worker_binary,
        &plan.unit_directory,
        &plan.controller_config,
    )?;
    ensure!(
        serde_json::to_value(plan)? == serde_json::to_value(&rebuilt)?,
        "Installation inputs changed; review a new plan"
    );
    let dir = plan.root.join("backup-server");
    let receipt = dir.join("installation.json");
    if receipt.try_exists()? {
        let r: Value = serde_json::from_slice(&super::transport::read_file(&receipt, true)?)?;
        ensure!(
            r["plan_sha256"] == plan.sha256 && r["state"] == "installed_inactive",
            "Incomplete/different install needs recovery review"
        );
        let expected_config = kagnode_backup_format::digest(&serde_json::to_vec(&plan.config)?);
        ensure!(
            protected_file_hash(&dir.join("config.json"), &[plan.worker_uid], true)?
                == expected_config
                && protected_file_hash(
                    &plan.controller_config,
                    &[plan.config.controller_uid.unwrap()],
                    true
                )? == expected_config
                && protected_file_hash(
                    &plan.unit_directory.join("kagnode-backup-server.service"),
                    &[0],
                    false
                )? == kagnode_backup_format::digest(plan.unit.as_bytes()),
            "Installed files changed; inspect before adopting the receipt"
        );
        return Ok(r);
    }
    let unit = plan.unit_directory.join("kagnode-backup-server.service");
    for p in [&dir, &plan.controller_config, &unit] {
        ensure!(
            matches!(p.symlink_metadata(),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
            "Existing files retained; review adoption separately"
        );
    }
    // Validate destination parents before making any changes.
    for p in [
        &plan.unit_directory,
        plan.controller_config.parent().unwrap(),
    ] {
        for a in p.ancestors() {
            let m = a.symlink_metadata()?;
            ensure!(
                m.is_dir()
                    && !m.file_type().is_symlink()
                    && (m.uid() == 0 || Some(m.uid()) == plan.config.controller_uid)
                    && (m.mode() & 0o022 == 0
                        || (a == Path::new("/tmp") && m.mode() & 0o1000 != 0)),
                "Unsafe install destination"
            );
        }
    }
    fs::create_dir(&dir)?;
    let raw = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(raw.as_ptr(), 0, plan.controller_gid) } == 0,
        "Cannot assign config directory group"
    );
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750))?;
    let mut r = json!({"state":"installing","plan_sha256":plan.sha256,"activation":false});
    create_owned(&receipt, &serde_json::to_vec(&r)?, 0o600, 0, 0)?;
    let bytes = serde_json::to_vec(&plan.config)?;
    create_owned(
        &dir.join("config.json"),
        &bytes,
        0o600,
        plan.worker_uid,
        plan.controller_gid,
    )?;
    create_owned(
        &plan.controller_config,
        &bytes,
        0o600,
        plan.config.controller_uid.unwrap(),
        plan.controller_gid,
    )?;
    create_owned(&unit, plan.unit.as_bytes(), 0o644, 0, 0)?;
    r["state"] = json!("installed_inactive");
    let temporary = dir.join("receipt-complete.tmp");
    create_owned(&temporary, &serde_json::to_vec(&r)?, 0o600, 0, 0)?;
    fs::rename(temporary, &receipt)?;
    fs::File::open(&dir)?.sync_all()?;
    Ok(r)
}

// Paths interpolated into a systemd unit must be checked before formatting:
// quoting is intentionally not supported, nor are systemd specifiers/expansions.
fn validate_unit_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "Invalid service destination path"
    );
    Ok(())
}
fn service_unit(
    worker_uid: u32,
    controller_gid: u32,
    binary: &Path,
    service_config: &Path,
    repository: &Path,
    controller_dir: &Path,
) -> Result<String> {
    for path in [binary, service_config, repository, controller_dir] {
        validate_unit_path(path)?;
    }
    Ok(format!(
        "[Unit]\nDescription=KagNode Backup Server\nAfter=network.target\n[Service]\nType=simple\nUser={}\nGroup={}\nExecStart={} serve --config {}\nRestart=on-failure\nRestartSec=5\nRuntimeDirectory=kagnode-backup\nRuntimeDirectoryMode=0750\nUMask=0077\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nPrivateDevices=true\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nReadWritePaths={} /run/kagnode-backup\nInaccessiblePaths={}\n[Install]\nWantedBy=multi-user.target\n",
        worker_uid,
        controller_gid,
        binary.display(),
        service_config.display(),
        repository.display(),
        controller_dir.display()
    ))
}

#[cfg(test)]
mod unit_path_tests {
    use super::*;
    #[test]
    fn worker_and_config_paths_are_validated_before_unit_rendering() {
        let safe = Path::new("/srv/kagnode/backup-server");
        for bad in [
            "/srv/worker binary",
            "/srv/worker\nExecStart=/bin/false",
            "/srv/%n",
            "/srv/$BIN",
            "/srv/worker;evil",
            "/srv/../worker",
            "relative",
            "/srv/é",
        ] {
            assert!(service_unit(1001, 1002, Path::new(bad), safe, safe, safe).is_err());
            assert!(service_unit(1001, 1002, safe, Path::new(bad), safe, safe).is_err());
        }
        let unit =
            service_unit(1001, 1002, safe, Path::new("/srv/config.json"), safe, safe).unwrap();
        assert!(
            unit.contains("ExecStart=/srv/kagnode/backup-server serve --config /srv/config.json\n")
        );
    }
}
