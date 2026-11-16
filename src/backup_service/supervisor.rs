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
        config.control_socket == Path::new("/run/kagnode-backup/admin.sock"),
        "Use the dedicated backup control socket"
    );
    let volume = config.repository.canonicalize()?;
    let controller = store.root.canonicalize()?;
    ensure!(
        !volume.starts_with(&controller) && !controller.starts_with(&volume),
        "Repository and control state must be disjoint"
    );
    let worker_uid = volume.metadata()?.uid();
    ensure!(
        worker_uid != 0 && worker_uid != unsafe { libc::geteuid() },
        "Backup worker requires a separate service account"
    );
    ensure!(
        config.controller_uid == Some(unsafe { libc::geteuid() }),
        "Backup configuration belongs to another controller"
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
/// The privileged service manager owns process lifetime, privilege separation and
/// sandboxing. Never fall back to spawning a network worker as the controller.
pub async fn request(
    store: &Store,
    request: &super::control::AdminRequest,
) -> Result<serde_json::Value> {
    let config =
        validate(store)?.ok_or_else(|| anyhow::anyhow!("Backup service is not configured"))?;
    super::control::request_from(
        &config.control_socket,
        request,
        config.repository.metadata()?.uid(),
    )
    .await
}
async fn cycle(store: &Store) -> Result<()> {
    if validate(store)?.is_some() {
        let value = request(store, &super::control::AdminRequest::Status).await?;
        ensure!(
            value["process_id"].is_u64(),
            "Backup service status is invalid"
        );
        status(store, "ready", "Dedicated backup service is responding");
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}
pub async fn supervise(store: Store) -> Result<()> {
    loop {
        if let Err(error) = cycle(&store).await {
            status(&store, "unavailable", &error.to_string());
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    }
}
