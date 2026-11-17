//! Backend CLI regressions; no installation, service calls or UI input.
use anyhow::Result;
use std::process::Command;
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_kagnode")
}
#[test]
fn profile_plan_rejects_systemd_continuations_and_substitutions_before_mutation() -> Result<()> {
    for origin in [
        "https://example.invalid\\",
        "https://$home.invalid",
        "https://%65xample.invalid",
        "https://example.invalid\"",
    ] {
        let output = Command::new(binary())
            .args(["install", "--print-plan", "--origin", origin])
            .output()?;
        assert!(!output.status.success(), "accepted unsafe origin: {origin}");
        assert!(
            output.stdout.is_empty(),
            "must not print an unsafe rendered plan"
        );
    }
    for origin in [
        "https://example.invalid",
        "https://example.invalid/",
        "https://example.invalid:8443",
        "http://127.0.0.1:8750",
        "https://[::1]:8443",
    ] {
        let output = Command::new(binary())
            .args(["install", "--print-plan", "--origin", origin])
            .output()?;
        assert!(
            output.status.success(),
            "safe origin refused: {origin}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
#[test]
fn native_regular_owner_is_explicitly_unavailable_before_host_mutation() -> Result<()> {
    let output = Command::new(binary())
        .args(["native-setup", "plan", "--owner-uid", "2000"])
        .output()?;
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr)?;
    if unsafe { libc::geteuid() } == 0 {
        assert!(error.contains("regular-owner transport is unavailable"));
    } else {
        assert!(error.contains("requires root"));
    }
    assert!(output.stdout.is_empty());
    Ok(())
}
#[test]
fn native_setup_has_no_password_command_argument() -> Result<()> {
    let output = Command::new(binary())
        .args(["native-setup", "apply", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("--password-stdin"));
    assert!(!help.contains("--password <"));
    Ok(())
}
