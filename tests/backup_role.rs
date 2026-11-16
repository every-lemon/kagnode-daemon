use anyhow::Result;
use kagnode_daemon::backup_service::role;
#[test]
fn reviewed_role_blocks_installation_and_rejects_changed_inventory() -> Result<()> {
    let t = tempfile::tempdir()?;
    let root = t.path().join("managed");
    let p = role::plan(&root)?;
    role::require_applications(&root)?;
    std::fs::create_dir(root.join("vpn"))?;
    assert!(role::apply(&root, &p).is_err());
    std::fs::remove_dir(root.join("vpn"))?;
    let receipt = role::apply(&root, &p)?;
    assert_eq!(receipt["state"], "reserved");
    assert!(role::require_applications(&root).is_err());
    assert_eq!(role::apply(&root, &p)?, receipt);
    let mut wrong = p;
    wrong.sha256 = "changed".into();
    assert!(role::apply(&root, &wrong).is_err());
    Ok(())
}
#[test]
fn role_lock_serializes_installers_and_bad_markers_fail_closed() -> Result<()> {
    let t = tempfile::tempdir()?;
    let root = t.path().join("managed");
    let lock = role::Guard::acquire(&root)?;
    assert!(role::plan(&root).is_err());
    drop(lock);
    std::os::unix::fs::symlink("missing", root.join(".kagnode-role.json"))?;
    assert!(role::require_applications(&root).is_err());
    assert!(role::plan(&root).is_err());
    Ok(())
}

#[test]
fn inactive_install_requires_valid_tls_and_preserves_existing_files() -> Result<()> {
    use kagnode_daemon::backup_service::transport::Config;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    if unsafe { libc::geteuid() } != 0
        || std::env::var("KAGNODE_PRIVILEGED_FIXTURE").as_deref() != Ok("1")
    {
        return Ok(());
    }
    let t = tempfile::tempdir()?;
    let root = t.path().join("managed");
    let reservation = role::plan(&root)?;
    role::apply(&root, &reservation)?;
    let controller = root.join("controller");
    fs::create_dir(&controller)?;
    fs::set_permissions(&controller, fs::Permissions::from_mode(0o700))?;
    let repository = t.path().join("repository");
    fs::create_dir(&repository)?;
    fs::set_permissions(&repository, fs::Permissions::from_mode(0o700))?;
    let chown = |path: &std::path::Path, uid: u32| -> Result<()> {
        let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        anyhow::ensure!(
            unsafe { libc::chown(p.as_ptr(), uid, uid) } == 0,
            "fixture chown"
        );
        Ok(())
    };
    chown(&repository, 65534)?;
    chown(&controller, 1)?;
    let cert = t.path().join("cert.pem");
    let key = t.path().join("key.pem");
    anyhow::ensure!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=fixture",
                "-days",
                "1",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout"
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success(),
        "fixture certificates"
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    chown(&key, 65534)?;
    let binary = t.path().join("worker");
    fs::write(&binary, b"fixture executable only; never executed")?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    let cfg = Config {
        repository,
        listen: "127.0.0.1:9443".parse()?,
        certificate: cert.clone(),
        private_key: key,
        client_ca: cert,
        control_socket: "/run/kagnode-backup/admin.sock".into(),
        controller_uid: Some(1),
    };
    let source = t.path().join("config.json");
    fs::write(&source, serde_json::to_vec(&cfg)?)?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
    let units = t.path().join("units");
    fs::create_dir(&units)?;
    let destination = controller.join("backup-server.json");
    let alias_dir = t.path().join("alias");
    fs::create_dir(&alias_dir)?;
    let noncanonical_binary = alias_dir.join("../worker");
    assert!(
        role::installation_plan(&root, &source, &noncanonical_binary, &units, &destination)
            .is_err(),
        "unit paths must not contain parent components"
    );
    let plan = role::installation_plan(&root, &source, &binary, &units, &destination)?;
    fs::write(&binary, b"changed binary")?;
    assert!(role::install(&plan).is_err());
    assert!(!destination.exists());
    let plan = role::installation_plan(&root, &source, &binary, &units, &destination)?;
    let receipt = role::install(&plan)?;
    assert_eq!(receipt["state"], "installed_inactive");
    assert_eq!(receipt["activation"], false);
    assert_eq!(role::install(&plan)?, receipt);
    assert!(units.join("kagnode-backup-server.service").exists());
    fs::write(
        units.join("kagnode-backup-server.service"),
        "tampered fixture",
    )?;
    assert!(role::install(&plan).is_err());
    Ok(())
}
