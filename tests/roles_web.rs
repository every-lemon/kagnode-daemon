use anyhow::Result;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use kagnode_daemon::{
    auth,
    roles::{self, Envelope},
    store::{Profile, Store},
    web::{self, App},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tower::ServiceExt;
static TEST_SERVER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
async fn request(
    r: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    csrf: &str,
    body: Value,
) -> Result<Response> {
    request_at(r, method, path, cookie, csrf, body, "192.0.2.1:3456").await
}
async fn request_at(
    r: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    csrf: &str,
    body: Value,
    peer: &str,
) -> Result<Response> {
    Ok(r.clone()
        .oneshot(
            Request::builder()
                .extension(axum::extract::ConnectInfo(
                    peer.parse::<std::net::SocketAddr>()?,
                ))
                .method(method)
                .uri(path)
                .header("origin", "http://localhost")
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(if method == "GET" {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })?,
        )
        .await?)
}
async fn value(r: Response) -> Result<Value> {
    Ok(serde_json::from_slice(
        &to_bytes(r.into_body(), 2_000_000).await?,
    )?)
}
fn body(action: Value, confirmation: Option<&str>) -> Value {
    json!({"request_id":auth::random().unwrap(),"confirmation":confirmation,"payload":action})
}
async fn login(r: &Router, account: &str) -> Result<(String, String)> {
    let challenge = request(r, "GET", "/api/v1/roles/auth", "", "", Value::Null).await?;
    let challenge_cookie = challenge.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let nonce = value(challenge).await?["csrf"].as_str().unwrap().to_owned();
    let response = request(
        r,
        "POST",
        "/api/v1/roles/login",
        &challenge_cookie,
        &nonce,
        body(
            json!({"action":"login","account":account,"password":"fixture-password-long"}),
            None,
        ),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let result = value(response).await?;
    assert!(result.get("token").is_none());
    Ok((cookie, result["csrf"].as_str().unwrap().to_owned()))
}
#[tokio::test]
async fn web_roles_enforce_scope_csrf_audience_confirmation_and_revocation() -> Result<()> {
    let _server = TEST_SERVER.lock().await;
    let dir = tempfile::tempdir()?;
    let s = Store::open(&dir.path().join("state"))?;
    s.init(
        "owner@fixture.invalid",
        "fixture-password-long",
        Profile::Light,
        false,
    )?;
    let db = Connection::open(s.root.join("daemon.sqlite"))?;
    for (id, role) in [("viewer", "viewer"), ("manager", "manager")] {
        db.execute(
            "INSERT INTO users VALUES(?1,?2,?3,?4,0,0,'fixture',1)",
            params![
                id,
                format!("{id}@fixture.invalid"),
                auth::hash_password("fixture-password-long")?,
                role
            ],
        )?;
    }
    db.execute(
        "INSERT INTO user_grants VALUES('manager','mail','view')",
        [],
    )?;
    let r = web::router(App {
        store: s.clone(),
        origin: "http://localhost".into(),
        core: std::sync::Arc::new(
            kagnode_core::Core::new(s.root.join("core"), "daemon")
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        ),
    });
    let (viewer, viewer_csrf) = login(&r, "viewer@fixture.invalid").await?;
    let (manager, manager_csrf) = login(&r, "manager@fixture.invalid").await?;
    let (operator, csrf) = login(&r, "owner@fixture.invalid").await?;
    for cookie in [&viewer, &manager, &operator] {
        let response =
            request(&r, "GET", "/api/v1/roles/overview", cookie, "", Value::Null).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let analytics = value(response).await?;
        assert!(analytics.get("nodes").is_some());
        assert!(!analytics.to_string().contains("password_hash"));
        assert_eq!(
            request(&r, "GET", "/api/v1/audit", cookie, "", Value::Null)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        request(&r, "GET", "/api/v1/roles/users", &operator, "", Value::Null)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    db.execute("UPDATE security_config SET admin_enabled=1", [])?;
    for cookie in [&viewer, &manager] {
        for path in ["users", "audit", "security"] {
            assert_eq!(
                request(
                    &r,
                    "GET",
                    &format!("/api/v1/roles/{path}"),
                    cookie,
                    "",
                    Value::Null
                )
                .await?
                .status(),
                StatusCode::FORBIDDEN
            );
        }
    }
    assert_eq!(
        request(
            &r,
            "GET",
            "/api/v1/roles/products/mail",
            &manager,
            "",
            Value::Null
        )
        .await?
        .status(),
        StatusCode::OK
    );
    for (cookie, path) in [(&viewer, "mail"), (&manager, "vpn")] {
        assert_eq!(
            request(
                &r,
                "GET",
                &format!("/api/v1/roles/products/{path}"),
                cookie,
                "",
                Value::Null
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    let target = json!({"action":"user_create","account":"new@fixture.invalid","password":"fixture-password-long","role":"viewer","grants":{}});
    let mutation = body(target.clone(), None);
    assert_eq!(
        request(
            &r,
            "POST",
            "/api/v1/roles/users-create",
            &operator,
            "wrong",
            mutation.clone()
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &r,
            "POST",
            "/api/v1/roles/users-create",
            &operator,
            &csrf,
            mutation
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    for (cookie, token) in [(&viewer, &viewer_csrf), (&manager, &manager_csrf)] {
        assert_eq!(request(&r,"POST","/api/v1/roles/confirm",cookie,token,body(json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),None)).await?.status(),StatusCode::FORBIDDEN);
    }
    let confirmation = request(
        &r,
        "POST",
        "/api/v1/roles/confirm",
        &operator,
        &csrf,
        body(
            json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),
            None,
        ),
    )
    .await?;
    assert_eq!(confirmation.status(), StatusCode::OK);
    let token = value(confirmation).await?["confirmation"]
        .as_str()
        .unwrap()
        .to_owned();
    let mutation = body(target, Some(&token));
    assert_eq!(
        request(
            &r,
            "POST",
            "/api/v1/roles/users-create",
            &operator,
            &csrf,
            mutation.clone()
        )
        .await?
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &r,
            "POST",
            "/api/v1/roles/users-create",
            &operator,
            &csrf,
            mutation
        )
        .await?
        .status(),
        StatusCode::FORBIDDEN
    );
    // Browser cookies cannot authenticate a local-socket request, including uid0.
    let e: Envelope = serde_json::from_value(
        json!({"version":1,"request_id":"cross-audience","session":operator.split_once('=').unwrap().1,"confirmation":null,"payload":{"action":"whoami"}}),
    )?;
    assert!(roles::handle(&s, 0, &e).is_err());
    assert!(roles::handle(&s, u32::MAX, &e).is_err());
    let root = body(
        json!({"action":"root_recover","account":"bad@fixture.invalid","password":"fixture-password-long"}),
        None,
    );
    assert_eq!(
        request(
            &r,
            "POST",
            "/api/v1/roles/root-recover",
            &operator,
            &csrf,
            root
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND
    );
    db.execute(
        "UPDATE users SET auth_revision=auth_revision+1 WHERE id='manager'",
        [],
    )?;
    assert_eq!(
        request(&r, "GET", "/api/v1/roles/whoami", &manager, "", Value::Null)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    db.execute("UPDATE security_config SET admin_enabled=0", [])?;
    assert_eq!(
        request(&r, "GET", "/api/v1/roles/users", &operator, "", Value::Null)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &r,
            "GET",
            "/api/v1/roles/overview",
            &viewer,
            "",
            Value::Null
        )
        .await?
        .status(),
        StatusCode::OK
    );
    Ok(())
}

async fn password_login_at(
    r: &Router,
    peer: &str,
    account: &str,
    password: &str,
) -> Result<Response> {
    let challenge = request(r, "GET", "/api/v1/roles/auth", "", "", Value::Null).await?;
    let cookie = challenge.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = value(challenge).await?["csrf"].as_str().unwrap().to_owned();
    request_at(
        r,
        "POST",
        "/api/v1/roles/login",
        &cookie,
        &csrf,
        body(
            json!({"action":"login","account":account,"password":password}),
            None,
        ),
        peer,
    )
    .await
}
fn web_fixture() -> Result<(tempfile::TempDir, Store, Router)> {
    let dir = tempfile::tempdir()?;
    let s = Store::open(&dir.path().join("state"))?;
    s.init(
        "owner@fixture.invalid",
        "fixture-password-long",
        Profile::Light,
        false,
    )?;
    let r = web::router(App {
        store: s.clone(),
        origin: "http://localhost".into(),
        core: std::sync::Arc::new(
            kagnode_core::Core::new(s.root.join("core"), "daemon")
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        ),
    });
    Ok((dir, s, r))
}
#[tokio::test]
async fn made_up_web_accounts_never_lock_other_accounts_or_terminal_global_budget() -> Result<()> {
    let _server = TEST_SERVER.lock().await;
    let (_dir, s, r) = web_fixture()?;
    for n in 0..60 {
        assert_eq!(
            password_login_at(
                &r,
                "192.0.2.1:1234",
                &format!("madeup{n}@fixture.invalid"),
                "wrong"
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    // Same peer/different account and different peer/different account both work.
    assert_eq!(
        password_login_at(
            &r,
            "192.0.2.1:1234",
            "owner@fixture.invalid",
            "fixture-password-long"
        )
        .await?
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        password_login_at(
            &r,
            "192.0.2.2:9876",
            "owner@fixture.invalid",
            "fixture-password-long"
        )
        .await?
        .status(),
        StatusCode::OK
    );
    let db = Connection::open(s.root.join("daemon.sqlite"))?;
    assert_eq!(db.query_row("SELECT COUNT(*) FROM security_attempts WHERE identity='global' OR identity='uid:4294967295'",[],|r|r.get::<_,i64>(0))?,0);
    for _ in 0..5 {
        assert_eq!(
            password_login_at(&r, "192.0.2.1:1234", "owner@fixture.invalid", "wrong")
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        password_login_at(
            &r,
            "192.0.2.1:1234",
            "owner@fixture.invalid",
            "fixture-password-long"
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Keep the real-account bucket across peers; a forwarded IP is not a bypass.
    assert_eq!(
        password_login_at(
            &r,
            "192.0.2.3:9876",
            "owner@fixture.invalid",
            "fixture-password-long"
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let e: Envelope = serde_json::from_value(
        json!({"version":1,"request_id":"terminal-after-web","session":null,"confirmation":null,"payload":{"action":"login","account":"owner@fixture.invalid","password":"fixture-password-long"}}),
    )?;
    assert!(roles::handle(&s, 42, &e).is_ok());
    Ok(())
}
#[tokio::test]
async fn nonexistent_user_errors_are_generic_and_oversized_role_bodies_are_rejected() -> Result<()>
{
    let _server = TEST_SERVER.lock().await;
    let (_dir, s, r) = web_fixture()?;
    Connection::open(s.root.join("daemon.sqlite"))?
        .execute("UPDATE security_config SET admin_enabled=1", [])?;
    let (cookie, csrf) = login(&r, "owner@fixture.invalid").await?;
    let target = json!({"action":"user_update","id":"does-not-exist","expected_revision":1,"role":"viewer","grants":{},"disabled":false});
    let proof=value(request(&r,"POST","/api/v1/roles/confirm",&cookie,&csrf,body(json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),None)).await?).await?;
    let response = request(
        &r,
        "POST",
        "/api/v1/roles/users-update",
        &cookie,
        &csrf,
        body(target, proof["confirmation"].as_str()),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        value(response).await?,
        json!({"error":"Request unavailable"})
    );
    let response = request(
        &r,
        "POST",
        "/api/v1/roles/login",
        "",
        "",
        json!({"padding":"x".repeat(20000)}),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}
