//! mTLS transport. Node requests are append-only and separately signed; admin actions use Unix IPC.
use super::repository::{Repository, SignedRequest, SignedSnapshot};
use crate::auth;
use anyhow::{Result, ensure};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use kagnode_backup_format::{MAX_MANIFEST_BYTES, digest, identifier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
pub type Shared = Arc<Mutex<Repository>>;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub repository: PathBuf,
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub client_ca: PathBuf,
    pub control_socket: PathBuf,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(&read_file(path, true)?)?;
        ensure!(
            value.repository.is_absolute() && value.control_socket.is_absolute(),
            "Use absolute repository and control paths"
        );
        Ok(value)
    }
}
pub fn read_file(path: &Path, secret: bool) -> Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.len() <= 1024 * 1024
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
            && m.mode() & 0o022 == 0
            && (!secret || m.mode() & 0o077 == 0),
        "Unsafe backup configuration/credential file"
    );
    let mut raw = Vec::new();
    f.take(1024 * 1024 + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 1024 * 1024, "Credential exceeds size limit");
    Ok(raw)
}
pub fn tls(config: &Config) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut read_file(&config.client_ca, false)?.as_slice()) {
        roots.add(c?)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let certs = rustls_pemfile::certs(&mut read_file(&config.certificate, false)?.as_slice())
        .collect::<std::io::Result<Vec<_>>>()?;
    let key_bytes = zeroize::Zeroizing::new(read_file(&config.private_key, true)?);
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("TLS key is missing"))?;
    let mut result = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    result.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(result))
}
#[derive(Clone)]
pub struct PeerCertificate(pub String);
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeRequest {
    Begin {
        snapshot: SignedSnapshot,
    },
    Renew {
        lease: String,
    },
    Offset {
        lease: String,
        object: String,
    },
    Upload {
        lease: String,
        object: String,
        offset: u64,
        data: String,
    },
    Finish {
        lease: String,
    },
    Status,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub node: String,
    pub token: String,
    pub proof: String,
}
fn field<'a>(h: &'a HeaderMap, name: &str) -> Result<&'a str> {
    h.get(name)
        .and_then(|s| s.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Missing authentication field"))
}
pub fn dispatch(
    repo: &mut Repository,
    node: &str,
    request: NodeRequest,
    now: i64,
) -> Result<Value> {
    match request {
        NodeRequest::Begin { snapshot } => {
            ensure!(snapshot.manifest.node == node, "Manifest node mismatch");
            Ok(serde_json::to_value(repo.begin(&snapshot, now)?)?)
        }
        NodeRequest::Renew { lease } => Ok(json!({"expires":repo.renew(node,&lease,now)?})),
        NodeRequest::Offset { lease, object } => {
            Ok(json!({"offset":repo.offset(node,&lease,&object,now)?}))
        }
        NodeRequest::Upload {
            lease,
            object,
            offset,
            data,
        } => {
            ensure!(data.len() <= 1_398_104, "Upload exceeds limit");
            let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
            Ok(json!({"offset":repo.upload(node,&lease,&object,offset,&bytes,now)?}))
        }
        NodeRequest::Finish { lease } => repo.finish(node, &lease, now),
        NodeRequest::Status => Ok(
            json!({"site":repo.identity.site,"server":repo.identity.server,"snapshots":repo.snapshots(node)?}),
        ),
    }
}
async fn node(
    State(state): State<Shared>,
    Extension(peer): Extension<PeerCertificate>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = tokio::task::spawn_blocking(move || -> Result<Value> {
        let node = field(&headers, "x-kagnode-node")?;
        let nonce = field(&headers, "x-kagnode-nonce")?;
        let at = field(&headers, "x-kagnode-time")?.parse()?;
        let signature = field(&headers, "x-kagnode-signature")?;
        ensure!(identifier(node), "Invalid node");
        let mut repo = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Storage unavailable"))?;
        repo.transport_identity(node, &peer.0)?;
        repo.rate_limit(node, auth::now())?;
        repo.authenticate(
            &SignedRequest {
                node,
                nonce,
                at,
                operation: "node",
                body: &body,
                signature,
            },
            auth::now(),
        )?;
        dispatch(&mut repo, node, serde_json::from_slice(&body)?, auth::now())
    })
    .await;
    match result {Ok(Ok(value))=>(StatusCode::OK,Json(json!({"ok":true,"value":value}))).into_response(),_ =>(StatusCode::CONFLICT,Json(json!({"ok":false,"error":"Request refused; verify identity, lease, quota and repository health"}))).into_response()}
}
async fn enroll(
    State(state): State<Shared>,
    Extension(peer): Extension<PeerCertificate>,
    Json(request): Json<Enrollment>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut repo = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Storage unavailable"))?;
        repo.transport_identity(&request.node, &peer.0)?;
        repo.enroll(&request.node, &request.token, &request.proof, auth::now())
    })
    .await;
    match result {
        Ok(Ok(())) => Json(json!({"ok":true})).into_response(),
        _ => (
            StatusCode::FORBIDDEN,
            Json(json!({"ok":false,"error":"Enrollment refused"})),
        )
            .into_response(),
    }
}
pub fn router(state: Shared, peer: PeerCertificate) -> Router {
    Router::new()
        .route("/api/v1/backup-server/node", post(node))
        .route(
            "/api/v1/backup-server/enroll",
            post(enroll).layer(DefaultBodyLimit::max(4096)),
        )
        .layer(DefaultBodyLimit::max(MAX_MANIFEST_BYTES + 2048))
        .layer(Extension(peer))
        .with_state(state)
}
pub async fn serve(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    state: Shared,
) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let limit = Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream))
                    .await
            else {
                return;
            };
            let Some(cert) = tls.get_ref().1.peer_certificates().and_then(|c| c.first()) else {
                return;
            };
            let app = router(state, PeerCertificate(digest(cert.as_ref())));
            let service = hyper_util::service::TowerToHyperService::new(app);
            let builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .http1_only();
            let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(tls), service);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(120), connection).await;
        });
    }
}
