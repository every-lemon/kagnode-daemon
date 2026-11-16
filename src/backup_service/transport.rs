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
    #[serde(default)]
    pub controller_uid: Option<u32>,
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
    let ca = read_file(&config.client_ca, false)?;
    let certificate = read_file(&config.certificate, false)?;
    let key = zeroize::Zeroizing::new(read_file(&config.private_key, true)?);
    tls_material(&ca, &certificate, &key)
}
pub(crate) fn tls_material(
    ca: &[u8],
    certificate: &[u8],
    key_bytes: &[u8],
) -> Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &*ca) {
        roots.add(c?)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let certs = rustls_pemfile::certs(&mut &*certificate).collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut &*key_bytes)?
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
#[derive(Clone, Default)]
struct Activity(Arc<std::sync::atomic::AtomicU64>);
struct Processing(Activity);
impl Activity {
    fn processing(&self) -> Processing {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Processing(self.clone())
    }
}
impl Drop for Processing {
    fn drop(&mut self) {
        self.0.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
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
    Extension(activity): Extension<Activity>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Bytes/Json extraction has finished; the server now owns the wait.
    let _processing = activity.processing();
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
    Extension(activity): Extension<Activity>,
    Json(request): Json<Enrollment>,
) -> Response {
    let _processing = activity.processing();
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
    router_activity(state, peer, Activity::default())
}
fn router_activity(state: Shared, peer: PeerCertificate, activity: Activity) -> Router {
    Router::new()
        .route("/api/v1/backup-server/node", post(node))
        .route(
            "/api/v1/backup-server/enroll",
            post(enroll).layer(DefaultBodyLimit::max(4096)),
        )
        .layer(DefaultBodyLimit::max(MAX_MANIFEST_BYTES + 2048))
        .layer(Extension(peer))
        .layer(Extension(activity))
        .with_state(state)
}
pub async fn serve(
    listener: tokio::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    state: Shared,
) -> Result<()> {
    let (_sender, receiver) = tokio::sync::watch::channel(config);
    serve_dynamic(listener, receiver, state).await
}
pub async fn serve_dynamic(
    listener: tokio::net::TcpListener,
    config: tokio::sync::watch::Receiver<Arc<rustls::ServerConfig>>,
    state: Shared,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(8));
    let certificates = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let handshakes = Arc::new(tokio::sync::Semaphore::new(32));
    let sources = Arc::new(Mutex::new(std::collections::HashMap::new()));
    loop {
        let (stream, address) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("Backup listener accept error: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
            continue;
        };
        let Some(source) = SourceSlot::acquire(sources.clone(), address.ip()) else {
            continue;
        };
        let mut generation = config.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(generation.borrow_and_update().clone());
        let state = state.clone();
        let limit = limit.clone();
        let certificates = certificates.clone();
        tokio::spawn(async move {
            let Ok(Ok(tls)) =
                tokio::time::timeout(std::time::Duration::from_secs(3), acceptor.accept(stream))
                    .await
            else {
                return;
            };
            let Some(cert) = tls.get_ref().1.peer_certificates().and_then(|c| c.first()) else {
                return;
            };
            let fingerprint = digest(cert.as_ref());
            // Retain the handshake bounds while approval is checked. This avoids
            // unbounded tasks waiting for the repository and excludes merely
            // CA-issued, expired enrollment and revoked identities from sessions.
            let approved = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    let verdict = match state.try_lock() {
                        Ok(repo) => Some(
                            repo.approved_transport(&fingerprint, auth::now())
                                .unwrap_or(false),
                        ),
                        Err(std::sync::TryLockError::WouldBlock) => None,
                        Err(_) => Some(false),
                    };
                    if let Some(approved) = verdict {
                        break approved;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            })
            .await;
            if !matches!(approved, Ok(true)) {
                return;
            }
            let Some(_certificate) = CertificateSlot::acquire(certificates, fingerprint.clone())
            else {
                return;
            };
            let Ok(_permit) = limit.try_acquire_owned() else {
                return;
            };
            drop(handshake);
            drop(source);
            let activity = Activity::default();
            let app = router_activity(state, PeerCertificate(fingerprint), activity.clone());
            let service = hyper_util::service::TowerToHyperService::new(app);
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .http1_only();
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(std::time::Duration::from_secs(12));
            let connection = builder.serve_connection(
                hyper_util::rt::TokioIo::new(IdleIo::new(tls, activity)),
                service,
            );
            tokio::select! {
                _ = tokio::time::timeout(std::time::Duration::from_secs(120), connection) => {},
                _ = generation.changed() => {}, // trust/certificate changes retire existing sessions
            }
        });
    }
}

// RAII cleanup also releases the per-source limit after timeout or cancellation.
struct SourceSlot {
    counts: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
    source: std::net::IpAddr,
}
impl SourceSlot {
    fn acquire(
        counts: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
        source: std::net::IpAddr,
    ) -> Option<Self> {
        {
            let mut map = counts.lock().ok()?;
            let count = map.entry(source).or_default();
            if *count >= 4 {
                return None;
            }
            *count += 1;
        }
        Some(Self { counts, source })
    }
}
impl Drop for SourceSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock()
            && let Some(count) = counts.get_mut(&self.source)
        {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.source);
            }
        }
    }
}

// Permit guards are scoped to the connection, including cancellation/error paths.
struct CertificateSlot {
    counts: Arc<Mutex<std::collections::HashMap<String, usize>>>,
    fingerprint: String,
}
impl CertificateSlot {
    fn acquire(
        counts: Arc<Mutex<std::collections::HashMap<String, usize>>>,
        fingerprint: String,
    ) -> Option<Self> {
        {
            let mut map = counts.lock().ok()?;
            let count = map.entry(fingerprint.clone()).or_default();
            if *count >= 2 {
                return None;
            }
            *count += 1;
        }
        Some(Self {
            counts,
            fingerprint,
        })
    }
}
impl Drop for CertificateSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.counts.lock()
            && let Some(count) = counts.get_mut(&self.fingerprint)
        {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.fingerprint);
            }
        }
    }
}

// Bounds silent keep-alive, partial bodies and stalled response readers. The
// separate absolute header deadline also stops one-byte header trickling.
struct IdleIo<T> {
    inner: T,
    phase: u64,
    activity: Activity,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
}
impl<T> IdleIo<T> {
    fn new(inner: T, activity: Activity) -> Self {
        Self {
            inner,
            phase: 0,
            activity,
            deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(12))),
        }
    }
    fn expired(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        let phase = self.activity.0.load(std::sync::atomic::Ordering::SeqCst);
        if self.phase != phase || phase % 2 == 1 {
            self.phase = phase;
            self.activity();
        }
        if phase % 2 == 1 {
            return false;
        }
        std::future::Future::poll(self.deadline.as_mut(), cx).is_ready()
    }
    fn activity(&mut self) {
        self.deadline
            .as_mut()
            .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(12));
    }
}
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleIo<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.expired(cx) {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity();
        }
        result
    }
}
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleIo<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.expired(cx) {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(n)) if n > 0) {
            self.activity();
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.expired(cx) {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Reload only a fully parsed, matching TLS material set. Invalid replacements
/// retain the old context. Receivers retire old sessions on a successful change.
pub struct TlsReloader {
    config: Config,
    fingerprint: String,
    sender: tokio::sync::watch::Sender<Arc<rustls::ServerConfig>>,
}
fn material(config: &Config) -> Result<(String, Arc<rustls::ServerConfig>)> {
    let ca = read_file(&config.client_ca, false)?;
    let cert = read_file(&config.certificate, false)?;
    let key = zeroize::Zeroizing::new(read_file(&config.private_key, true)?);
    let fingerprint = format!("{}:{}:{}", digest(&ca), digest(&cert), digest(&key));
    Ok((fingerprint, tls_material(&ca, &cert, &key)?))
}
impl TlsReloader {
    pub fn new(
        config: Config,
    ) -> Result<(
        Self,
        tokio::sync::watch::Receiver<Arc<rustls::ServerConfig>>,
    )> {
        let (fingerprint, tls) = material(&config)?;
        let (sender, receiver) = tokio::sync::watch::channel(tls);
        Ok((
            Self {
                config,
                fingerprint,
                sender,
            },
            receiver,
        ))
    }
    pub fn reload(&mut self) -> Result<bool> {
        let (fingerprint, tls) = material(&self.config)?;
        if fingerprint == self.fingerprint {
            return Ok(false);
        }
        self.sender.send_replace(tls);
        self.fingerprint = fingerprint;
        Ok(true)
    }
    pub async fn watch(mut self) -> Result<()> {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        loop {
            tokio::select! {_=tokio::time::sleep(std::time::Duration::from_secs(30))=>{},_=signal.recv()=>{}}
            let (next, result) = tokio::task::spawn_blocking(move || {
                let result = self.reload();
                (self, result)
            })
            .await?;
            self = next;
            match result {
                Ok(true) => eprintln!("Backup TLS context reloaded; prior sessions retired"),
                Ok(false) => {}
                Err(_) => eprintln!("Backup TLS replacement rejected; previous context retained"),
            }
        }
    }
}
