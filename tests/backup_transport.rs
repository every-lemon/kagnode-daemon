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
    for action in ["approve", "delete"] {
        let body = if action == "approve" {
            serde_json::json!({"action":"approve","node":"node","public_key":"a".repeat(64),"certificate_sha256":"b".repeat(64)})
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
