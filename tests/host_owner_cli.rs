use anyhow::Result;
use kagnode_daemon::store::{Profile, Store};
use std::process::Command;
#[test]
fn legacy_cli_is_explicit_host_owner_and_does_not_send_obsolete_protocol() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("state");
    let s = Store::open(&path)?;
    s.init(
        "owner@fixture.invalid",
        "fixture-password-long",
        Profile::Light,
        false,
    )?;
    for command in ["status", "monitor", "retention"] {
        let help = Command::new(env!("CARGO_BIN_EXE_kagnode"))
            .args([command, "--help"])
            .output()?;
        assert!(String::from_utf8_lossy(&help.stdout).contains("Host-owner"));
        // No running socket is required: this is explicitly the host-owner interface.
        let result = Command::new(env!("CARGO_BIN_EXE_kagnode"))
            .arg("--root")
            .arg(&path)
            .arg(command)
            .output()?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let _: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    }
    let missing = tmp.path().join("missing");
    let result = Command::new(env!("CARGO_BIN_EXE_kagnode"))
        .arg("--root")
        .arg(&missing)
        .arg("status")
        .output()?;
    assert!(!result.status.success());
    assert!(!missing.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("existing installation"));
    if unsafe { libc::geteuid() } == 0 {
        use std::os::unix::process::CommandExt;
        let result = Command::new(env!("CARGO_BIN_EXE_kagnode"))
            .uid(65534)
            .gid(65534)
            .arg("--root")
            .arg(&path)
            .arg("status")
            .output();
        match result {
            Ok(output) => assert!(!output.status.success()),
            // Data-disk builds may be below an owner-only /root. Refusal to
            // execute there is filesystem isolation, not UID runtime qualification.
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        }
    }
    Ok(())
}
