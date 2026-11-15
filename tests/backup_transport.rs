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
    agent.enroll(token).await?;
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
    Ok(())
}
struct Process(std::process::Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unprivileged_process_is_supervised_without_dashboard() -> Result<()> {
    let binary = std::env::var("KAGNODE_BACKUP_BINARY")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_kagnode-backup-server").into());
    if unsafe { libc::geteuid() } == 0 {
        let result = Command::new(&binary)
            .args(["serve", "--config", "/nonexistent-fixture"])
            .output()?;
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("unprivileged"));
        return Ok(());
    }
    let main_binary = std::env::var("KAGNODE_DAEMON_BINARY")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_kagnode").into());
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    certificates(root)?;
    let controller = root.join("daemon/controller");
    let store = kagnode_daemon::store::Store::open(&controller)?;
    store.init(
        "owner@fixture.invalid",
        "fixture-password-long",
        kagnode_daemon::store::Profile::Light,
        false,
    )?;
    let repository = root.join("repository");
    drop(Repository::create(
        &repository,
        "site",
        "server",
        &policy(),
    )?);
    let config = Config {
        repository,
        listen: "127.0.0.1:0".parse()?,
        certificate: root.join("server.pem"),
        private_key: root.join("server.key"),
        client_ca: root.join("ca.pem"),
        control_socket: controller.join("run/backup-server.sock"),
    };
    let path = controller.join("backup-server.json");
    fs::write(&path, serde_json::to_vec(&config)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let mut daemon = Process(
        Command::new(&main_binary)
            .arg("--root")
            .arg(&controller)
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut first = None;
    for _ in 0..100 {
        if let Ok(value) = control::request(&config.control_socket, &AdminRequest::Status).await {
            first = value["process_id"].as_u64();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let first = first.ok_or_else(|| anyhow::anyhow!("Supervised backup worker did not start"))?;
    assert!(
        kagnode_daemon::runtime::request(&controller, &kagnode_daemon::runtime::Request::Overview)
            .is_ok()
    );
    ensure!(
        unsafe { libc::kill(first as i32, libc::SIGKILL) } == 0,
        "Cannot interrupt fixture child"
    );
    let mut second = None;
    for _ in 0..450 {
        if let Ok(value) = control::request(&config.control_socket, &AdminRequest::Status).await {
            let pid = value["process_id"].as_u64();
            if pid.is_some() && pid != Some(first) {
                second = pid;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ensure!(
        second.is_some(),
        "Daemon failed to restart interrupted backup worker"
    );
    assert!(
        kagnode_daemon::runtime::request(&controller, &kagnode_daemon::runtime::Request::Overview)
            .is_ok()
    );
    ensure!(
        unsafe { libc::kill(daemon.0.id() as i32, libc::SIGTERM) } == 0,
        "Cannot terminate fixture Daemon"
    );
    ensure!(daemon.0.wait()?.success(), "Daemon did not stop cleanly");
    Ok(())
}
