//! Local owner-only administration. Remote source agents never reach this socket.
use super::{policy::Policy, transport::Shared};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    Status,
    Approve {
        node: String,
        public_key: String,
        certificate_sha256: String,
    },
    Revoke {
        node: String,
    },
    Snapshots {
        node: String,
    },
    SetPolicy {
        policy: Policy,
    },
    Pin {
        node: String,
        snapshot: String,
        pinned: bool,
    },
    Delete {
        node: String,
        snapshot: String,
        confirm: String,
    },
    CollectGarbage {
        confirm: bool,
    },
}
impl AdminRequest {
    pub fn action(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Approve { .. } => "approve",
            Self::Revoke { .. } => "revoke",
            Self::Snapshots { .. } => "snapshots",
            Self::SetPolicy { .. } => "policy",
            Self::Pin { .. } => "pin",
            Self::Delete { .. } => "delete",
            Self::CollectGarbage { .. } => "garbage-collection",
        }
    }
    pub fn needs_confirmation(&self) -> bool {
        !matches!(
            self,
            Self::Status | Self::Snapshots { .. } | Self::Pin { pinned: true, .. }
        )
    }
}
pub fn dispatch(shared: &Shared, req: AdminRequest) -> Result<Value> {
    dispatch_as(shared, req, unsafe { libc::geteuid() })
}
fn dispatch_as(shared: &Shared, req: AdminRequest, uid: u32) -> Result<Value> {
    let mut r = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("Storage unavailable"))?;
    let actor = format!("control:uid:{uid}");
    r.admin_actor = actor.clone();
    match req {
        AdminRequest::Status => {
            let (total, available) = r.capacity()?;
            Ok(
                json!({"process_id":std::process::id(),"site":r.identity.site,"server":r.identity.server,"policy":r.policy()?,"storage_total_bytes":total,"storage_available_bytes":available,"verification":"ciphertext checks are not restore qualification"}),
            )
        }
        AdminRequest::Approve {
            node,
            public_key,
            certificate_sha256,
        } => Ok(
            json!({"node":node,"expires_in":600,"token":r.approve_tls_node(&node,&public_key,&certificate_sha256,crate::auth::now())?}),
        ),
        AdminRequest::Revoke { node } => {
            r.revoke(&node)?;
            Ok(json!({"revoked":true}))
        }
        AdminRequest::Snapshots { node } => {
            Ok(json!({"snapshots":r.snapshots(&node)?,"protected":r.protected(&node)?}))
        }
        AdminRequest::SetPolicy { policy } => {
            r.save_policy(&policy, &actor)?;
            Ok(json!({"revision":policy.revision}))
        }
        AdminRequest::Pin {
            node,
            snapshot,
            pinned,
        } => {
            r.pin(&node, &snapshot, pinned)?;
            Ok(json!({"pinned":pinned}))
        }
        AdminRequest::Delete {
            node,
            snapshot,
            confirm,
        } => {
            ensure!(
                confirm == format!("delete {node}/{snapshot}"),
                "Confirm the exact snapshot identity"
            );
            r.delete(&node, &snapshot, &actor)?;
            Ok(json!({"deleted":true}))
        }
        AdminRequest::CollectGarbage { confirm } => {
            ensure!(confirm, "Garbage collection requires confirmation");
            Ok(json!({"objects_removed":r.gc(crate::auth::now())?}))
        }
    }
}
pub async fn serve(path: &Path, shared: Shared) -> Result<()> {
    serve_for(path, shared, unsafe { libc::geteuid() }).await
}
pub async fn serve_for(path: &Path, shared: Shared, controller_uid: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Socket parent missing"))?;
    let m = parent.symlink_metadata()?;
    ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o027 == 0,
        "Control socket needs a private owned directory"
    );
    if let Ok(m) = path.symlink_metadata() {
        ensure!(
            m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() },
            "Unexpected control socket file"
        );
        ensure!(
            UnixStream::connect(path).await.is_err(),
            "Control service already active"
        );
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if controller_uid == unsafe { libc::geteuid() } {
            0o600
        } else {
            0o660
        }),
    )?;
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    loop {
        let (stream, _) = listener.accept().await?;
        let uid = stream.peer_cred()?.uid();
        if uid != 0 && uid != controller_uid {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let input = tokio::time::timeout(
                Duration::from_secs(5),
                (&mut reader).take(16385).read_line(&mut line),
            )
            .await;
            let result = if matches!(input, Ok(Ok(_))) && line.len() <= 16384 {
                match serde_json::from_str::<AdminRequest>(&line) {
                    Ok(req) => tokio::task::spawn_blocking(move || dispatch_as(&shared, req, uid))
                        .await
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("Control worker failed"))),
                    Err(_) => Err(anyhow::anyhow!("Invalid control request")),
                }
            } else {
                Err(anyhow::anyhow!("Control request exceeded limits"))
            };
            let value = match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(e) => json!({"ok":false,"error":e.to_string()}),
            };
            let mut stream = reader.into_inner();
            let _ = stream
                .write_all(&serde_json::to_vec(&value).unwrap_or_default())
                .await;
            let _ = stream.shutdown().await;
        });
    }
}
pub async fn request(path: &Path, request: &AdminRequest) -> Result<Value> {
    request_from(path, request, unsafe { libc::geteuid() }).await
}
pub async fn request_from(path: &Path, request: &AdminRequest, worker_uid: u32) -> Result<Value> {
    let m = path.symlink_metadata()?;
    ensure!(
        m.file_type().is_socket()
            && m.mode() & 0o007 == 0
            && (m.uid() == worker_uid || unsafe { libc::geteuid() } == 0),
        "Unsafe control socket"
    );
    let mut stream = UnixStream::connect(path).await?;
    ensure!(
        stream.peer_cred()?.uid() == worker_uid,
        "Unexpected backup control service identity"
    );
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    let value = tokio::time::timeout(Duration::from_secs(30), async {
        stream.write_all(&bytes).await?;
        let mut bytes = Vec::new();
        stream
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await?;
        anyhow::ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "Control response exceeds limit"
        );
        Ok::<Value, anyhow::Error>(serde_json::from_slice(&bytes)?)
    })
    .await??;
    ensure!(
        value["ok"] == true,
        "{}",
        value["error"].as_str().unwrap_or("Control request failed")
    );
    Ok(value["value"].clone())
}
