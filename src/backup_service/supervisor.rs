//! Optional child process: independent of web/TUI lifetime, restarted by the Daemon.
use super::transport::Config;
use crate::{catalog, store::Store};
use anyhow::{Result, ensure};
use std::{os::unix::fs::MetadataExt, path::Path, time::Duration};
/// Refuse ambiguous product directories too; an unrecognized install is not an empty node.
pub fn require_exclusive(managed_root: &Path) -> Result<()> {
    for product in catalog::PRODUCTS {
        let path = managed_root.join(product.id);
        ensure!(
            matches!(path.symlink_metadata(),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
            "Backup Server role conflicts with existing {} files",
            product.name
        );
    }
    for alias in ["pm", "authentactor", "authenticator", "cli", "http-boot"] {
        ensure!(
            matches!(managed_root.join(alias).symlink_metadata(),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
            "Legacy product files need review before enabling Backup Server"
        );
    }
    Ok(())
}
pub fn validate(store: &Store) -> Result<Option<Config>> {
    let path = store.root.join("backup-server.json");
    match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    require_exclusive(store.managed_root())?;
    let config = Config::load(&path)?;
    ensure!(
        config.control_socket == store.root.join("run/backup-server.sock"),
        "Use Daemon's private backup control socket"
    );
    let volume = config.repository.canonicalize()?;
    let controller = store.root.canonicalize()?;
    ensure!(
        !volume.starts_with(&controller) && !controller.starts_with(&volume),
        "Repository and control state must be disjoint"
    );
    Ok(Some(config))
}
pub fn child_binary() -> Result<std::path::PathBuf> {
    let path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Executable parent missing"))?
        .join("kagnode-backup-server");
    let m = path.symlink_metadata()?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
            && m.mode() & 0o022 == 0,
        "Unsafe backup-server executable"
    );
    Ok(path)
}
fn status(store: &Store, state: &str, message: &str) {
    if let Ok(old) = store.document("backup-worker") {
        let revision = old.map_or(0, |(r, _)| r);
        let _ = store.save_document(
            "backup-supervisor",
            "backup-worker",
            revision,
            &serde_json::json!({"state":state,"message":message,"updated_at":crate::auth::now()}),
        );
    }
}
async fn cycle(store: &Store) -> Result<()> {
    let Some(initial) = validate(store)? else {
        tokio::time::sleep(Duration::from_secs(2)).await;
        return Ok(());
    };
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Backup supervision requires an unprivileged Daemon"
    );
    let mut child = tokio::process::Command::new(child_binary()?)
        .arg("serve")
        .arg("--config")
        .arg(store.root.join("backup-server.json"))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    status(
        store,
        "starting",
        "Backup worker process started; consult its control socket for readiness",
    );
    loop {
        tokio::select! {
            result=child.wait()=>{let result=result?;anyhow::bail!("Backup worker exited with {result}");},
            _=tokio::time::sleep(Duration::from_secs(2))=>{
                if validate(store)?.as_ref()!=Some(&initial){child.kill().await?;let _=child.wait().await;status(store,"reconfiguring","Backup configuration changed or was disabled");return Ok(());}
            }
        }
    }
}
pub async fn supervise(store: Store) -> Result<()> {
    loop {
        if let Err(error) = cycle(&store).await {
            status(&store, "unavailable", &error.to_string());
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    }
}
