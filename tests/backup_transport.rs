use anyhow::{Result, ensure};
use kagnode_backup_format::{Manifest, digest};
use kagnode_daemon::backup_service::{
    agent::{Agent, Target},
    control::{self, AdminRequest},
    policy::Policy,
    repository::Repository,
    supervisor,
    transport::{self, Config, Shared},
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
fn openssl(path: &Path, args: &[&str]) -> Result<()> {
    ensure!(
        Command::new("openssl")
            .current_dir(path)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success(),
        "Fixture certificate generation failed"
    );
    Ok(())
}
fn certificates(path: &Path) -> Result<()> {
    openssl(
        path,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            "/CN=Disposable Backup Test CA",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    )?;
    for name in ["server", "client", "other"] {
        openssl(
            path,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        )?;
        fs::write(
            path.join("extension"),
            if name == "server" {
                "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
            } else {
                "extendedKeyUsage=clientAuth\n"
            },
        )?;
        openssl(
            path,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                &format!("{name}.pem"),
                "-days",
                "1",
                "-extfile",
                "extension",
            ],
        )?;
        let mut pem = fs::read(path.join(format!("{name}.pem")))?;
        pem.extend_from_slice(&fs::read(path.join(format!("{name}.key")))?);
        let p = path.join(format!("{name}-identity.pem"));
        fs::write(&p, pem)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn policy() -> Policy {
    Policy {
        revision: 1,
        interval_seconds: 3600,
        recovery_point_seconds: 7200,
        keep_snapshots: 3,
        reserve_bytes: 0,
        max_deferral_seconds: 86400,
        bandwidth_percent: 25,
        monthly_node_bytes: None,
        monthly_server_bytes: None,
        required_copies: 1,
    }
}
fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[55; 32]).unwrap()
}
fn fingerprint(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let cert = rustls_pemfile::certs(&mut bytes.as_slice())
        .next()
        .unwrap()?;
    Ok(digest(cert.as_ref()))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_signed_upload_admin_separation_and_restart() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    certificates(root)?;
    let repository = root.join("repository");
    let shared: Shared = Arc::new(Mutex::new(Repository::create(
        &repository,
        "site",
        "server",
        &policy(),
    )?));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let config = Config {
        controller_uid: None,
        repository: repository.clone(),
        listen: address,
        certificate: root.join("server.pem"),
        private_key: root.join("server.key"),
        client_ca: root.join("ca.pem"),
        control_socket: root.join("control.sock"),
    };
    let tls = transport::tls(&config)?;
    let server = tokio::spawn(transport::serve(listener, tls.clone(), shared.clone()));
    let admin = tokio::spawn({
        let p = config.control_socket.clone();
        let s = shared.clone();
        async move { control::serve(&p, s).await }
    });
    for _ in 0..50 {
        if config.control_socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ensure!(
        config.control_socket.exists(),
        "Local administration socket did not start"
    );
    let target = Target {
        site: "site".into(),
        server: "server".into(),
        endpoint: format!("https://{address}"),
        ca: root.join("ca.pem"),
        identity_pem: root.join("client-identity.pem"),
    };
    let agent = Agent::new("node", key(), target.clone())?;
    assert!(
        agent.status().await.is_err(),
        "Unapproved identity rejected"
    );
    let ticket = control::request(
        &config.control_socket,
        &AdminRequest::Approve {
            node: "node".into(),
            public_key: hex::encode(key().public_key().as_ref()),
            certificate_sha256: fingerprint(&root.join("client.pem"))?,
        },
    )
    .await?;
    let token = ticket["token"].as_str().unwrap();
    let mut other = target.clone();
    other.identity_pem = root.join("other-identity.pem");
    let impostor = Agent::new("node", key(), other)?;
    assert!(
        impostor.enroll(token).await.is_err(),
        "A trusted but unbound certificate must fail"
    );
    let mut silent_peers = Vec::new();
    for _ in 0..8 {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind("127.0.0.2:0".parse()?)?;
        silent_peers.push(socket.connect(address).await?);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let fresh_agent = Agent::new("node", key(), target.clone())?;
    tokio::time::timeout(Duration::from_secs(2), fresh_agent.enroll(token)).await??;
    drop(fresh_agent);
    drop(silent_peers);
    assert!(agent.enroll(token).await.is_err());
    assert!(impostor.status().await.is_err());
    let cert = reqwest::Certificate::from_pem(&fs::read(root.join("ca.pem"))?)?;
    let unauthenticated = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .no_proxy()
        .build()?;
    assert!(
        unauthenticated
            .post(format!("https://{address}/api/v1/backup-server/node"))
            .json(&serde_json::json!({"operation":"status"}))
            .send()
            .await
            .is_err(),
        "TLS requires a client certificate"
    );
    let objects = root.join("objects");
    fs::create_dir(&objects)?;
    let input = root.join("input");
    fs::create_dir(&input)?;
    fs::write(
        input.join("fixture.txt"),
        b"synthetic vault data for isolated recovery",
    )?;
    let recovery = age::x25519::Identity::generate();
    let manifest = kagnode_backup_format::snapshot(
        &input,
        &objects,
        &recovery.to_public().to_string(),
        &mut kagnode_backup_format::ChunkIndex::default(),
        Manifest {
            format: "kagnode-dbackup/v2".into(),
            site: "site".into(),
            node: "node".into(),
            snapshot: "first".into(),
            created_at: kagnode_daemon::auth::now(),
            recipient_generation: "initial".into(),
            catalog: kagnode_backup_format::Object {
                sha256: "0".repeat(64),
                bytes: 1,
            },
            objects: vec![],
        },
    )?;
    let receipt = agent.push(manifest.clone(), &objects).await?;
    assert_eq!(receipt["ciphertext_verified"], true);
    assert_eq!(receipt["restore_tested"], false);
    assert_eq!(
        agent.push(manifest.clone(), &objects).await?,
        receipt,
        "Lost acknowledgment retries remain idempotent"
    );
    assert_eq!(
        agent.status().await?["snapshots"].as_array().unwrap().len(),
        1
    );
    assert!(
        control::request(
            &config.control_socket,
            &AdminRequest::Delete {
                node: "node".into(),
                snapshot: "first".into(),
                confirm: "delete node/first".into()
            }
        )
        .await
        .is_err()
    );
    control::request(
        &config.control_socket,
        &AdminRequest::Revoke {
            node: "node".into(),
        },
    )
    .await?;
    assert!(agent.status().await.is_err());
    server.abort();
    admin.abort();
    let _ = server.await;
    let _ = admin.await;
    drop(agent);
    drop(impostor);
    drop(shared);
    // Detached connection tasks may need to observe the client's closed pool before releasing storage.
    let mut reopened = None;
    for _ in 0..100 {
        if let Ok(repo) = Repository::open(&repository) {
            reopened = Some(repo);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let restored = reopened.ok_or_else(|| anyhow::anyhow!("Repository owner did not release"))?;
    assert_eq!(restored.snapshots("node")?.len(), 1);
    assert_eq!(
        kagnode_backup_format::restore(
            &manifest,
            &repository.join("objects/node"),
            &recovery,
            &root.join("recovered"),
            1024
        )?,
        1
    );
    assert_eq!(
        fs::read(root.join("recovered/fixture.txt"))?,
        b"synthetic vault data for isolated recovery"
    );
    assert!(restored.public_key("node").is_err());
    Ok(())
}
#[test]
fn exclusive_role_refuses_unknown_and_legacy_product_files() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    supervisor::require_exclusive(tmp.path())?;
    fs::create_dir(tmp.path().join("passwords"))?;
    assert!(supervisor::require_exclusive(tmp.path()).is_err());
    fs::remove_dir(tmp.path().join("passwords"))?;
    std::os::unix::fs::symlink("nonexistent", tmp.path().join("mail"))?;
    assert!(supervisor::require_exclusive(tmp.path()).is_err());
    Ok(())
}
#[tokio::test]
async fn dashboard_backup_actions_need_session_and_csrf() -> Result<()> {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use kagnode_daemon::{
        store::{Profile, Store},
        web::{App, router},
    };
    use tower::ServiceExt;
    let tmp = tempfile::tempdir()?;
    let store = Store::open(tmp.path())?;
    store.init(
        "owner@fixture.invalid",
        "fixture-password-long",
        Profile::Light,
        true,
    )?;
    let token = store.login("owner@fixture.invalid", "fixture-password-long", "test")?;
    let csrf = store.session(&token)?.unwrap().csrf;
    let app = router(App {
        store,
        origin: "http://127.0.0.1:8750".into(),
        core: Arc::new(
            kagnode_core::Core::new("/nonexistent-core", "daemon")
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        ),
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/backup-server/status")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/backup-server/status")
                .header("cookie", format!("kn_daemon={token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/backup-server/actions")
                .method("POST")
                .header("cookie", format!("kn_daemon={token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"action":"revoke","node":"target"}"#))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    for action in ["approve", "delete", "rotate-certificate"] {
        let body = if action == "approve" {
            serde_json::json!({"action":"approve","node":"node","public_key":"a".repeat(64),"certificate_sha256":"b".repeat(64)})
        } else if action == "rotate-certificate" {
            serde_json::json!({"action":"rotate_certificate","node":"node","expected_sha256":"a".repeat(64),"certificate_sha256":"b".repeat(64)})
        } else {
            serde_json::json!({"action":"delete","node":"node","snapshot":"one","confirm":"delete node/one"})
        };
        let send = |path: String, body: serde_json::Value, confirmation: &str| {
            Request::builder()
                .uri(path)
                .method("POST")
                .header("cookie", format!("kn_daemon={token}"))
                .header("origin", "http://127.0.0.1:8750")
                .header("x-csrf-token", &csrf)
                .header("x-backup-confirmation", confirmation)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let response = app
            .clone()
            .oneshot(send(
                format!("/api/v1/backup-server/{action}"),
                body.clone(),
                "",
            ))
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(send(
                "/api/v1/backup-server/confirm".into(),
                serde_json::json!({"password":"fixture-password-long","request":body}),
                "",
            ))
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let challenge = value["confirmation"].as_str().unwrap();
        let mut changed = body.clone();
        changed["node"] = serde_json::json!("another-node");
        let response = app
            .clone()
            .oneshot(send(
                format!("/api/v1/backup-server/{action}"),
                changed,
                challenge,
            ))
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "confirmation is bound to the exact request"
        );
        let response = app
            .clone()
            .oneshot(send(
                format!("/api/v1/backup-server/{action}"),
                body.clone(),
                challenge,
            ))
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "confirmed action reaches unconfigured worker"
        );
        let response = app
            .clone()
            .oneshot(send(
                format!("/api/v1/backup-server/{action}"),
                body,
                challenge,
            ))
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "challenge must not replay"
        );
    }
    Ok(())
}

#[test]
fn f7_same_identity_worker_is_rejected() -> Result<()> {
    let binary = std::env::var("KAGNODE_BACKUP_BINARY")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_kagnode-backup-server").into());
    let tmp = tempfile::tempdir()?;
    let config = Config {
        repository: tmp.path().join("repository"),
        listen: "127.0.0.1:0".parse()?,
        certificate: tmp.path().join("cert"),
        private_key: tmp.path().join("key"),
        client_ca: tmp.path().join("ca"),
        control_socket: tmp.path().join("control.sock"),
        controller_uid: Some(unsafe { libc::geteuid() }),
    };
    let p = tmp.path().join("config");
    fs::write(&p, serde_json::to_vec(&config)?)?;
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    let result = Command::new(binary)
        .arg("serve")
        .arg("--config")
        .arg(p)
        .output()?;
    assert!(!result.status.success());
    let err = String::from_utf8_lossy(&result.stderr);
    assert!(
        err.contains("separate service account") || err.contains("unprivileged"),
        "{err}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f9_agent_refuses_server_requests_outside_its_manifest() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tmp = tempfile::tempdir()?;
    certificates(tmp.path())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let config = Config {
        repository: tmp.path().join("unused"),
        listen: address,
        certificate: tmp.path().join("server.pem"),
        private_key: tmp.path().join("server.key"),
        client_ca: tmp.path().join("ca.pem"),
        control_socket: tmp.path().join("unused.sock"),
        controller_uid: None,
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(transport::tls(&config)?);
    let stolen = b"ciphertext belonging to another snapshot";
    let object = kagnode_backup_format::Object {
        sha256: digest(stolen),
        bytes: stolen.len() as u64,
    };
    let objects = tmp.path().join("objects");
    fs::create_dir(&objects)?;
    fs::write(objects.join(&object.sha256), stolen)?;
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let fake = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(tls.read_u8().await.unwrap());
            }
            let length = String::from_utf8_lossy(&header)
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|s| s.parse::<usize>().ok())
                })
                .unwrap();
            let mut body = vec![0; length];
            tls.read_exact(&mut body).await.unwrap();
            let n = observed.fetch_add(1, Ordering::SeqCst);
            let value = match n {
                0 => serde_json::json!({"id":"lease","expires":i64::MAX,"missing":[object]}),
                1 => serde_json::json!({"offset":0}),
                2 => serde_json::json!({"offset":stolen.len()}),
                _ => serde_json::json!({"ciphertext_verified":true}),
            };
            let reply = serde_json::json!({"ok":true,"value":value}).to_string();
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",reply.len(),reply).as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
        }
    });
    let agent = Agent::new(
        "node",
        key(),
        Target {
            site: "site".into(),
            server: "server".into(),
            endpoint: format!("https://{address}"),
            ca: tmp.path().join("ca.pem"),
            identity_pem: tmp.path().join("client-identity.pem"),
        },
    )?;
    let manifest = Manifest {
        format: "kagnode-dbackup/v2".into(),
        site: "site".into(),
        node: "node".into(),
        snapshot: "one".into(),
        created_at: kagnode_daemon::auth::now(),
        recipient_generation: "initial".into(),
        catalog: kagnode_backup_format::Object {
            sha256: digest(b"authorized catalog"),
            bytes: 18,
        },
        objects: vec![],
    };
    let result = agent.push(manifest, &objects).await;
    fake.abort();
    let _ = fake.await;
    assert!(result.is_err());
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "Agent must refuse before reading/uploading another snapshot's object"
    );
    Ok(())
}

/// Opt-in disposable root fixture only; it creates numeric-UID processes, never users/services.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f7_worker_has_separate_uid_empty_environment_and_no_inherited_fd() -> Result<()> {
    use std::os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    };
    if unsafe { libc::geteuid() } != 0 || std::env::var_os("KAGNODE_PRIVILEGED_FIXTURE").is_none() {
        eprintln!("SKIP numeric-UID fixture: requires isolated root test namespace");
        return Ok(());
    }
    struct Child(Command, Option<std::process::Child>);
    impl Drop for Child {
        fn drop(&mut self) {
            if let Some(c) = self.1.as_mut() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    certificates(root)?;
    let binary = root.join("worker");
    fs::copy(env!("CARGO_BIN_EXE_kagnode-backup-server"), &binary)?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))?;
    let state = root.join("state");
    fs::create_dir(&state)?;
    let set_owner = |p: &Path, uid: u32, gid: u32| -> Result<()> {
        let p = std::ffi::CString::new(p.to_str().unwrap())?;
        ensure!(
            unsafe { libc::chown(p.as_ptr(), uid, gid) } == 0,
            "fixture chown failed"
        );
        Ok(())
    };
    set_owner(&state, 1002, 1002)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    for name in ["ca.pem", "server.pem", "server.key"] {
        fs::copy(root.join(name), state.join(name))?;
        set_owner(&state.join(name), 1002, 1002)?;
        fs::set_permissions(state.join(name), fs::Permissions::from_mode(0o600))?;
    }
    let policy_path = state.join("policy");
    fs::write(&policy_path, serde_json::to_vec(&policy())?)?;
    set_owner(&policy_path, 1002, 1002)?;
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600))?;
    let command = || {
        let mut c = Command::new(&binary);
        c.uid(1002).gid(1002);
        c
    };
    let result = command()
        .arg("init")
        .arg("--directory")
        .arg(state.join("repository"))
        .args(["--site", "site", "--server", "server", "--policy"])
        .arg(&policy_path)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let config = Config {
        repository: state.join("repository"),
        listen: "127.0.0.1:0".parse()?,
        certificate: state.join("server.pem"),
        private_key: state.join("server.key"),
        client_ca: state.join("ca.pem"),
        control_socket: state.join("control.sock"),
        controller_uid: Some(1001),
    };
    let path = state.join("config");
    fs::write(&path, serde_json::to_vec(&config)?)?;
    set_owner(&path, 1002, 1002)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let private = root.join("controller-private");
    fs::create_dir(&private)?;
    set_owner(&private, 1001, 1001)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
    fs::write(
        private.join("synthetic-state"),
        b"synthetic controller-only data",
    )?;
    let inherited = fs::File::open(private.join("synthetic-state"))?;
    assert_eq!(
        unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let mut child = Child(command(), None);
    child.1 = Some(
        child
            .0
            .arg("serve")
            .arg("--config")
            .arg(&path)
            .env("KAGNODE_SYNTHETIC_SECRET", "must-not-inherit")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    unsafe {
        libc::fcntl(inherited.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let pid = child.1.as_ref().unwrap().id();
    let mut ready = false;
    for _ in 0..100 {
        if control::request_from(&config.control_socket, &AdminRequest::Status, 1002)
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready, "isolated worker failed to start");
    assert_eq!(fs::metadata(format!("/proc/{pid}"))?.uid(), 1002);
    assert!(fs::read(format!("/proc/{pid}/environ"))?.is_empty());
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        assert_ne!(
            fs::read_link(entry.path()).ok(),
            Some(private.join("synthetic-state"))
        );
    }
    let denied = Command::new("/bin/cat")
        .arg(private.join("synthetic-state"))
        .uid(1002)
        .gid(1002)
        .output()?;
    assert!(
        !denied.status.success(),
        "worker UID could read controller state"
    );
    Ok(())
}

struct SessionFixture {
    root: tempfile::TempDir,
    shared: Shared,
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Drop for SessionFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl SessionFixture {
    async fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        certificates(root.path())?;
        let shared = Arc::new(Mutex::new(Repository::create(
            &root.path().join("repo"),
            "site",
            "server",
            &policy(),
        )?));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let cfg = Config {
            repository: root.path().join("repo"),
            listen: address,
            certificate: root.path().join("server.pem"),
            private_key: root.path().join("server.key"),
            client_ca: root.path().join("ca.pem"),
            control_socket: root.path().join("control.sock"),
            controller_uid: None,
        };
        let task = tokio::spawn(transport::serve(
            listener,
            transport::tls(&cfg)?,
            shared.clone(),
        ));
        Ok(Self {
            root,
            shared,
            address,
            task,
        })
    }
    fn approve(&self, name: &str) -> Result<()> {
        self.shared.lock().unwrap().approve_tls_node(
            name,
            &hex::encode(key().public_key().as_ref()),
            &fingerprint(&self.root.path().join(format!("{name}.pem")))?,
            kagnode_daemon::auth::now(),
        )?;
        Ok(())
    }
    async fn connect(
        &self,
        name: &str,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let root = self.root.path();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut fs::read(root.join("ca.pem"))?.as_slice()) {
            roots.add(cert?)?;
        }
        let certs =
            rustls_pemfile::certs(&mut fs::read(root.join(format!("{name}.pem")))?.as_slice())
                .collect::<std::io::Result<Vec<_>>>()?;
        let private_key = rustls_pemfile::private_key(
            &mut fs::read(root.join(format!("{name}.key")))?.as_slice(),
        )?
        .unwrap();
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, private_key)?;
        let socket = tokio::net::TcpStream::connect(self.address).await?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::IpAddress(self.address.ip().into()),
                socket,
            )
            .await?;
        // TLS client completion can precede the server processing its Finished.
        tokio::time::sleep(Duration::from_millis(30)).await;
        Ok(stream)
    }
    async fn responds(&self, name: &str) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = self.connect(name).await?;
        stream
            .write_all(b"GET /missing HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await?;
        let mut bytes = [0; 128];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes)).await??;
        ensure!(
            n > 0 && bytes[..n].starts_with(b"HTTP/1.1 404"),
            "Unrelated approved node lost its HTTP session"
        );
        Ok(())
    }
}
async fn session_closed(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    within: Duration,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(within, async {
        let mut buf = [0; 512];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn residual_f6_unapproved_certificates_never_hold_sessions() -> Result<()> {
    let f = SessionFixture::new().await?;
    f.approve("other")?;
    let mut peers = Vec::new();
    for _ in 0..8 {
        peers.push(f.connect("client").await?);
    }
    f.responds("other").await?;
    for peer in &mut peers {
        session_closed(peer, Duration::from_secs(2)).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn residual_f6_certificate_cap_releases_and_preserves_other_nodes() -> Result<()> {
    let f = SessionFixture::new().await?;
    f.approve("client")?;
    f.approve("other")?;
    let first = f.connect("client").await?;
    let second = f.connect("client").await?;
    let mut excess = f.connect("client").await?;
    session_closed(&mut excess, Duration::from_secs(2)).await?;
    f.responds("other").await?;
    drop((first, second));
    tokio::time::sleep(Duration::from_millis(100)).await;
    f.responds("client").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn residual_f6_header_body_and_keepalive_deadlines() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = SessionFixture::new().await?;
    f.approve("client")?;
    f.approve("other")?;
    let mut silent = f.connect("client").await?;
    let mut header = f.connect("client").await?;
    header
        .write_all(b"POST /api/v1/backup-server/node HTTP/1.1\r\nHost:")
        .await?;
    let mut body = f.connect("other").await?;
    body.write_all(
        b"POST /api/v1/backup-server/node HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\n{",
    )
    .await?;
    let mut keepalive = f.connect("other").await?;
    keepalive
        .write_all(b"GET /missing HTTP/1.1\r\nHost: test\r\n\r\n")
        .await?;
    let mut response = [0; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), keepalive.read(&mut response)).await??;
    assert!(response[..n].starts_with(b"HTTP/1.1 404"));
    tokio::try_join!(
        session_closed(&mut silent, Duration::from_secs(15)),
        session_closed(&mut header, Duration::from_secs(15)),
        session_closed(&mut body, Duration::from_secs(15)),
        session_closed(&mut keepalive, Duration::from_secs(15)),
    )?;
    f.responds("client").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn residual_f6_revoked_and_expired_pending_certificates_rejected() -> Result<()> {
    let f = SessionFixture::new().await?;
    let target = Target {
        site: "site".into(),
        server: "server".into(),
        endpoint: format!("https://{}", f.address),
        ca: f.root.path().join("ca.pem"),
        identity_pem: f.root.path().join("client-identity.pem"),
    };
    let agent = Agent::new("client", key(), target)?;
    let token = f.shared.lock().unwrap().approve_tls_node(
        "client",
        &agent.public_key(),
        &fingerprint(&f.root.path().join("client.pem"))?,
        kagnode_daemon::auth::now(),
    )?;
    agent.enroll(&token).await?;
    f.shared.lock().unwrap().revoke("client")?;
    let mut revoked = f.connect("client").await?;
    session_closed(&mut revoked, Duration::from_secs(2)).await?;
    f.shared.lock().unwrap().approve_tls_node(
        "other",
        &agent.public_key(),
        &fingerprint(&f.root.path().join("other.pem"))?,
        kagnode_daemon::auth::now() - 601,
    )?;
    let mut expired = f.connect("other").await?;
    session_closed(&mut expired, Duration::from_secs(2)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_transfer_resumes_acknowledged_partial_and_reuses_receipt() -> Result<()> {
    use kagnode_daemon::backup_service::repository::SignedSnapshot;
    let f = SessionFixture::new().await?;
    let target = Target {
        site: "site".into(),
        server: "server".into(),
        endpoint: format!("https://{}", f.address),
        ca: f.root.path().join("ca.pem"),
        identity_pem: f.root.path().join("client-identity.pem"),
    };
    let agent = Agent::new("client", key(), target.clone())?;
    let token = f.shared.lock().unwrap().approve_tls_node(
        "client",
        &agent.public_key(),
        &fingerprint(&f.root.path().join("client.pem"))?,
        kagnode_daemon::auth::now(),
    )?;
    agent.enroll(&token).await?;
    let payload = vec![42; 2 * 1024 * 1024];
    let objects = f.root.path().join("objects");
    fs::create_dir(&objects)?;
    let hash = digest(&payload);
    fs::write(objects.join(&hash), &payload)?;
    let manifest = Manifest {
        format: "kagnode-dbackup/v2".into(),
        site: "site".into(),
        node: "client".into(),
        snapshot: "resume".into(),
        created_at: kagnode_daemon::auth::now(),
        recipient_generation: "initial".into(),
        catalog: kagnode_backup_format::Object {
            sha256: hash.clone(),
            bytes: payload.len() as u64,
        },
        objects: vec![],
    };
    let signed = SignedSnapshot {
        signature: hex::encode(key().sign(&manifest.bytes()?).as_ref()),
        manifest: manifest.clone(),
    };
    let id = {
        let mut r = f.shared.lock().unwrap();
        let l = r.begin(&signed, kagnode_daemon::auth::now())?;
        r.upload(
            "client",
            &l.id,
            &hash,
            0,
            &payload[..65536],
            kagnode_daemon::auth::now(),
        )?;
        l.id
    };
    drop(agent); // New client process state; acknowledged offset stays at the server.
    let restarted = Agent::new("client", key(), target)?;
    assert_eq!(
        f.shared
            .lock()
            .unwrap()
            .offset("client", &id, &hash, kagnode_daemon::auth::now())?,
        65536
    );
    let start = std::time::Instant::now();
    let receipt = restarted
        .push_limited(manifest.clone(), &objects, 1024 * 1024)
        .await?;
    assert!(
        start.elapsed() >= Duration::from_millis(1900),
        "Explicit bandwidth ceiling was bypassed"
    );
    assert_eq!(restarted.push(manifest, &objects).await?, receipt);
    assert_eq!(f.shared.lock().unwrap().snapshots("client")?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn residual_f6_lock_wait_bounded_without_timing_out_server_processing() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = SessionFixture::new().await?;
    f.approve("client")?;
    let mut admitted = f.connect("client").await?;
    let (tx, rx) = std::sync::mpsc::channel();
    let repo = f.shared.clone();
    let holder = std::thread::spawn(move || {
        let _guard = repo.lock().unwrap();
        tx.send(()).unwrap();
        std::thread::sleep(Duration::from_secs(16));
    });
    rx.recv()?;
    let body = r#"{"node":"client","token":"invalid","proof":"invalid"}"#;
    admitted.write_all(format!("POST /api/v1/backup-server/enroll HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await?;
    let mut new = f.connect("client").await?;
    let bounded = session_closed(&mut new, Duration::from_secs(5)).await;
    let mut response = Vec::new();
    // Abrupt TLS EOF is allowed after a complete HTTP response; inspect the bytes.
    let _ =
        tokio::time::timeout(Duration::from_secs(20), admitted.read_to_end(&mut response)).await?;
    holder.join().unwrap();
    bounded?;
    assert!(
        response.starts_with(b"HTTP/1.1 403"),
        "Server-side processing was incorrectly treated as client inactivity"
    );
    f.responds("client").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_rotation_revokes_old_sessions_and_pending_approvals() -> Result<()> {
    let f = SessionFixture::new().await?;
    let old = fingerprint(&f.root.path().join("client.pem"))?;
    let new = fingerprint(&f.root.path().join("other.pem"))?;
    let mut target = Target {
        site: "site".into(),
        server: "server".into(),
        endpoint: format!("https://{}", f.address),
        ca: f.root.path().join("ca.pem"),
        identity_pem: f.root.path().join("client-identity.pem"),
    };
    let agent = Agent::new("client", key(), target.clone())?;
    let ticket = f.shared.lock().unwrap().approve_tls_node(
        "client",
        &agent.public_key(),
        &old,
        kagnode_daemon::auth::now(),
    )?;
    agent.enroll(&ticket).await?;
    agent.status().await?;
    {
        let mut r = f.shared.lock().unwrap();
        r.rotate_certificate("client", &old, &new, kagnode_daemon::auth::now())?;
        r.rotate_certificate("client", &old, &new, kagnode_daemon::auth::now())?;
        assert!(
            r.rotate_certificate("client", &old, &"c".repeat(64), kagnode_daemon::auth::now())
                .is_err()
        );
        assert!(
            r.rotate_certificate("client", &new, &old, kagnode_daemon::auth::now())
                .is_err()
        );
    }
    assert!(
        agent.status().await.is_err(),
        "Existing pooled old certificate stayed authorized"
    );
    target.identity_pem = f.root.path().join("other-identity.pem");
    let rotated = Agent::new("client", key(), target)?;
    rotated.status().await?;
    let mut r = f.shared.lock().unwrap();
    r.revoke("client")?;
    assert!(!r.approved_transport(&new, kagnode_daemon::auth::now())?);
    r.approve_tls_node(
        "pending",
        &agent.public_key(),
        &"d".repeat(64),
        kagnode_daemon::auth::now(),
    )?;
    r.revoke("pending")?;
    assert!(!r.approved_transport(&"d".repeat(64), kagnode_daemon::auth::now())?);
    assert!(
        r.approve_tls_node(
            "replacement",
            &agent.public_key(),
            &new,
            kagnode_daemon::auth::now()
        )
        .is_err()
    );
    assert!(
        AdminRequest::RotateCertificate {
            node: "client".into(),
            expected_sha256: old,
            certificate_sha256: new
        }
        .needs_confirmation()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_reload_retires_sessions_and_rejects_invalid_material() -> Result<()> {
    let mut f = SessionFixture::new().await?;
    f.approve("client")?;
    f.task.abort();
    while !f.task.is_finished() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let listener = tokio::net::TcpListener::bind(f.address).await?;
    let root = f.root.path();
    let cfg = Config {
        repository: root.join("repo"),
        listen: f.address,
        certificate: root.join("server.pem"),
        private_key: root.join("server.key"),
        client_ca: root.join("ca.pem"),
        control_socket: root.join("admin.sock"),
        controller_uid: None,
    };
    let (mut reload, rx) = transport::TlsReloader::new(cfg)?;
    f.task = tokio::spawn(transport::serve_dynamic(listener, rx, f.shared.clone()));
    f.responds("client").await?;
    assert!(!reload.reload()?);
    let root = f.root.path();
    let saved = fs::read(root.join("server.key"))?;
    fs::write(root.join("server.key"), b"invalid key")?;
    assert!(reload.reload().is_err());
    f.responds("client").await?;
    fs::write(root.join("server.key"), saved)?;
    let mut old = f.connect("client").await?;
    fs::write(
        root.join("server-extension"),
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
    )?;
    openssl(
        root,
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            "20261115",
            "-out",
            "server-next.pem",
            "-days",
            "1",
            "-extfile",
            "server-extension",
        ],
    )?;
    fs::rename(root.join("server-next.pem"), root.join("server.pem"))?;
    assert!(reload.reload()?);
    session_closed(&mut old, Duration::from_secs(2)).await?;
    f.responds("client").await?;
    Ok(())
}
