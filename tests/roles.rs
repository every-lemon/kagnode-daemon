use anyhow::Result;
use kagnode_daemon::{
    auth,
    roles::{self, Action, Envelope, Level, Principal, Role},
    runtime,
    store::{Profile, Store},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
fn call(
    s: &Store,
    uid: u32,
    token: Option<&str>,
    payload: Value,
    confirmation: Option<&str>,
) -> Result<Value> {
    let e: Envelope = serde_json::from_value(
        json!({"version":1,"request_id":auth::random()?,"session":token,"confirmation":confirmation,"payload":payload}),
    )?;
    roles::handle(s, uid, &e)
}
fn fixture() -> Result<(tempfile::TempDir, Store)> {
    let t = tempfile::tempdir()?;
    let s = Store::open(&t.path().join("state"))?;
    s.init(
        "owner@fixture.invalid",
        "fixture-password-long",
        Profile::Light,
        false,
    )?;
    Ok((t, s))
}
fn login(s: &Store, uid: u32, account: &str) -> Result<String> {
    Ok(call(
        s,
        uid,
        None,
        json!({"action":"login","account":account,"password":"fixture-password-long"}),
        None,
    )?["token"]
        .as_str()
        .unwrap()
        .into())
}
fn confirmed(s: &Store, uid: u32, token: &str, target: Value) -> Result<Value> {
    let confirmation = call(
        s,
        uid,
        Some(token),
        json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),
        None,
    )?;
    call(
        s,
        uid,
        Some(token),
        target,
        confirmation["confirmation"].as_str(),
    )
}
fn db(s: &Store) -> Result<Connection> {
    Ok(Connection::open(s.root.join("daemon.sqlite"))?)
}
fn add_fixture(s: &Store, id: &str, role: &str) -> Result<()> {
    db(s)?.execute(
        "INSERT INTO users VALUES(?1,?2,?3,?4,0,0,'synthetic-fixture',1)",
        params![
            id,
            format!("{id}@fixture.invalid"),
            auth::hash_password("fixture-password-long")?,
            role
        ],
    )?;
    Ok(())
}
#[test]
fn matrix_denies_unknown_and_scopes_every_product() -> Result<()> {
    let actions = [
        ("product_status", Level::View),
        ("core_status", Level::View),
        ("logs", Level::Operate),
        ("backup_pin", Level::Operate),
        ("boot_set", Level::Manage),
        ("core_plan", Level::Manage),
        ("core_apply", Level::Manage),
        ("core_rollback", Level::Manage),
        ("core_policy", Level::Manage),
        ("backup_read", Level::View),
        ("backup_manage", Level::Manage),
    ];
    for role in [Role::Operator, Role::Manager, Role::Viewer] {
        for grant in [
            None,
            Some(Level::View),
            Some(Level::Operate),
            Some(Level::Manage),
        ] {
            let mut p = Principal {
                id: "fixture".into(),
                account: "fixture@test.invalid".into(),
                role,
                disabled: false,
                auth_revision: 1,
                created_at: 0,
                created_by: "fixture".into(),
                grants: BTreeMap::new(),
            };
            if let Some(l) = grant {
                p.grants.insert("mail".into(), l);
                p.grants.insert("backup".into(), l);
            }
            for (a, needed) in actions {
                let product = if a.starts_with("backup_") {
                    "backup"
                } else {
                    "mail"
                };
                assert_eq!(
                    roles::permits(&p, a, Some(product)),
                    role == Role::Operator
                        || (role == Role::Manager && grant.is_some_and(|l| l >= needed)),
                    "{role:?} {grant:?} {a}"
                );
                assert!(!roles::permits(&p, a, Some("../../root")));
                assert!(!roles::permits(&p, a, None));
            }
            for a in ["overview", "metrics", "retention", "whoami", "logout"] {
                assert!(roles::permits(&p, a, None));
                assert!(!roles::permits(&p, a, Some("mail")));
            }
            for a in [
                "user_list",
                "user_create",
                "security_get",
                "security_set",
                "audit",
                "global_manage",
            ] {
                assert_eq!(roles::permits(&p, a, None), role == Role::Operator);
            }
            assert!(!roles::permits(&p, "shell", None));
            p.disabled = true;
            assert!(!roles::permits(&p, "overview", None));
        }
    }
    Ok(())
}
#[test]
fn migration_preserves_legacy_hashes_settings_and_invalidates_sessions_once() -> Result<()> {
    let (t, s) = fixture()?;
    let path = s.root.clone();
    let hash: String = db(&s)?.query_row("SELECT password_hash FROM admins", [], |r| r.get(0))?;
    let legacy = s.login("owner@fixture.invalid", "fixture-password-long", "fixture")?;
    db(&s)?.execute_batch("DROP TABLE terminal_confirmations;DROP TABLE terminal_sessions;DROP TABLE user_grants;DROP TABLE users;DROP TABLE security_config;")?;
    drop(s);
    let s = Store::open(&path)?;
    assert!(s.session(&legacy)?.is_none());
    assert!(!s.settings()?.web_enabled);
    assert!(s.require_web_admin().is_err());
    let (h, r, creator): (String, String, String) =
        db(&s)?.query_row("SELECT password_hash,role,created_by FROM users", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    assert_eq!(h, hash);
    assert_eq!(r, "operator");
    assert_eq!(creator, "migration");
    let tok = login(&s, 10, "owner@fixture.invalid")?;
    drop(s);
    let s = Store::open(&path)?;
    assert_eq!(
        call(&s, 10, Some(&tok), json!({"action":"whoami"}), None)?["user"]["role"],
        "operator"
    );
    assert_eq!(
        db(&s)?.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))?,
        1
    );
    drop(t);
    Ok(())
}
#[test]
fn role_changes_revoke_every_session_and_last_operator_is_protected() -> Result<()> {
    let (_t, s) = fixture()?;
    let owner = login(&s, 42, "owner@fixture.invalid")?;
    let id = call(&s, 42, Some(&owner), json!({"action":"whoami"}), None)?["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(confirmed(&s,42,&owner,json!({"action":"user_update","id":id,"expected_revision":1,"role":"viewer","grants":{},"disabled":false})).is_err());
    let made = confirmed(
        &s,
        42,
        &owner,
        json!({"action":"user_create","account":"manager@fixture.invalid","password":"fixture-password-long","role":"manager","grants":{"mail":"operate"}}),
    )?;
    let mid = made["user"]["id"].as_str().unwrap();
    assert_eq!(made["user"]["created_by"], id);
    let mt = login(&s, 43, "manager@fixture.invalid")?;
    assert!(call(&s, 43, Some(&mt), json!({"action":"user_list"}), None).is_err());
    assert!(
        call(
            &s,
            43,
            Some(&mt),
            json!({"action":"product_status","product":"mail"}),
            None
        )
        .is_ok()
    );
    assert!(
        call(
            &s,
            43,
            Some(&mt),
            json!({"action":"product_status","product":"vpn"}),
            None
        )
        .is_err()
    );
    confirmed(
        &s,
        42,
        &owner,
        json!({"action":"user_update","id":mid,"expected_revision":1,"role":"viewer","grants":{},"disabled":false}),
    )?;
    assert!(call(&s, 43, Some(&mt), json!({"action":"whoami"}), None).is_err());
    assert_eq!(
        db(&s)?.query_row(
            "SELECT COUNT(*) FROM user_grants WHERE user_id=?1",
            [mid],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    assert!(
        s.login("manager@fixture.invalid", "fixture-password-long", "legacy")
            .is_err()
    );
    Ok(())
}
#[test]
fn confirmations_bind_action_uid_revision_and_cannot_replay_failed_mutations() -> Result<()> {
    let (_t, s) = fixture()?;
    let token = login(&s, 9, "owner@fixture.invalid")?;
    assert!(call(&s, 10, Some(&token), json!({"action":"whoami"}), None).is_err());
    let target = json!({"action":"security_set","expected_revision":1,"admin_enabled":true});
    let c = call(
        &s,
        9,
        Some(&token),
        json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),
        None,
    )?;
    let c = c["confirmation"].as_str().unwrap();
    assert!(
        call(
            &s,
            9,
            Some(&token),
            json!({"action":"security_set","expected_revision":1,"admin_enabled":false}),
            Some(c)
        )
        .is_err()
    );
    call(&s, 9, Some(&token), target.clone(), Some(c))?;
    assert!(s.require_web_admin().is_ok());
    assert!(call(&s, 9, Some(&token), target.clone(), Some(c)).is_err());
    // Conflict consumes the freshly bound token even though transaction refuses.
    let c = call(
        &s,
        9,
        Some(&token),
        json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),
        None,
    )?;
    assert!(
        call(
            &s,
            9,
            Some(&token),
            target.clone(),
            c["confirmation"].as_str()
        )
        .is_err()
    );
    assert_eq!(
        db(&s)?.query_row("SELECT COUNT(*) FROM terminal_confirmations", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert!(!s.settings()?.web_enabled); // admin gate did not change dashboard setting
    let count:i64=db(&s)?.query_row("SELECT COUNT(*) FROM security_receipts WHERE actor=(SELECT id FROM users) AND uid=9 AND action='security_set'",[],|r|r.get(0))?;
    assert_eq!(count, 1);
    let raw: String =
        db(&s)?.query_row("SELECT GROUP_CONCAT(detail) FROM audit", [], |r| r.get(0))?;
    assert!(!raw.contains(&token) && !raw.contains("fixture-password-long"));
    Ok(())
}
#[test]
fn authentication_limits_expiry_restart_and_unknown_fields() -> Result<()> {
    let (_t, s) = fixture()?;
    for _ in 0..5 {
        assert!(call(&s,21,None,json!({"action":"login","account":"missing@fixture.invalid","password":"bad-password"}),None).is_err());
    }
    let count: i64 = db(&s)?.query_row(
        "SELECT count FROM security_attempts WHERE identity LIKE 'id:21:%'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 5);
    let root = s.root.clone();
    drop(s);
    let s = Store::open(&root)?;
    assert!(
        call(
            &s,
            21,
            None,
            json!({"action":"login","account":"missing@fixture.invalid","password":"bad-password"}),
            None
        )
        .unwrap_err()
        .to_string()
        .contains("retry later")
    );
    let tok = login(&s, 22, "owner@fixture.invalid")?;
    db(&s)?.execute(
        "UPDATE terminal_sessions SET last_use=?1",
        [auth::now() - 901],
    )?;
    assert!(call(&s, 22, Some(&tok), json!({"action":"whoami"}), None).is_err());
    let tok = login(&s, 23, "owner@fixture.invalid")?;
    db(&s)?.execute("UPDATE terminal_sessions SET expires=0", [])?;
    assert!(call(&s, 23, Some(&tok), json!({"action":"whoami"}), None).is_err());
    assert!(serde_json::from_value::<Envelope>(json!({"version":1,"request_id":"x","session":null,"confirmation":null,"actor":"operator","payload":{"action":"whoami"}})).is_err());
    assert!(serde_json::from_value::<Action>(json!({"action":"user_create","account":"x@y.invalid","password":"fixture-password-long","role":"operator","grants":{},"created_by":"forged"})).is_err());
    Ok(())
}
#[test]
fn owner_mode_restart_enable_protection_and_root_recovery() -> Result<()> {
    let t = tempfile::tempdir()?;
    let root = t.path().join("state");
    let s = Store::open(&root)?;
    let uid = unsafe { libc::geteuid() };
    roles::init_owner(&s, uid, Profile::Light)?;
    assert!(s.require_web_admin().is_err());
    assert!(
        call(
            &s,
            uid.wrapping_add(1),
            None,
            json!({"action":"owner_session"}),
            None
        )
        .is_err()
    );
    drop(s);
    let s = Store::open(&root)?;
    let r = call(&s, uid, None, json!({"action":"owner_session"}), None)?;
    let token = r["token"].as_str().unwrap();
    assert_eq!(r["whoami"]["protection"], "unprotected");
    assert!(call(&s,uid,Some(token),json!({"action":"user_create","account":"new@fixture.invalid","password":"fixture-password-long","role":"operator","grants":{}}),None).is_err());
    call(
        &s,
        uid,
        Some(token),
        json!({"action":"enable_protection","account":"owner@fixture.invalid","password":"fixture-password-long"}),
        None,
    )?;
    assert!(call(&s, uid, Some(token), json!({"action":"whoami"}), None).is_err());
    assert!(call(&s, uid, None, json!({"action":"owner_session"}), None).is_err());
    assert!(roles::init_owner(&s, uid, Profile::Light).is_err());
    let tok = login(&s, uid, "owner@fixture.invalid")?;
    assert!(call(&s,1001,None,json!({"action":"root_recover","account":"owner@fixture.invalid","password":"recovery-password-long"}),None).is_err());
    call(
        &s,
        0,
        None,
        json!({"action":"root_recover","account":"owner@fixture.invalid","password":"recovery-password-long"}),
        None,
    )?;
    assert!(call(&s, uid, Some(&tok), json!({"action":"whoami"}), None).is_err());
    assert!(s.require_web_admin().is_err());
    assert!(call(&s,uid,None,json!({"action":"login","account":"owner@fixture.invalid","password":"recovery-password-long"}),None).is_ok());
    Ok(())
}
#[test]
fn viewer_analytics_do_not_contain_admin_inventory_or_audit() -> Result<()> {
    let (_t, s) = fixture()?;
    add_fixture(&s, "viewer", "viewer")?;
    let token = login(&s, 44, "viewer@fixture.invalid")?;
    let request: Envelope = serde_json::from_value(
        json!({"version":1,"request_id":"viewer-read","session":token,"confirmation":null,"payload":{"action":"overview"}}),
    )?;
    let v = runtime::authenticated_dispatch(&s, 44, request)?;
    assert!(
        v.get("audit").is_none() && v.get("applications").is_none() && v.get("profile").is_none()
    );
    assert!(
        call(
            &s,
            44,
            Some(&token),
            json!({"action":"backup_agent_status"}),
            None
        )
        .is_err()
    );
    assert!(
        s.login("viewer@fixture.invalid", "fixture-password-long", "web")
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn socket_rejects_legacy_and_binds_real_peer_uid() -> Result<()> {
    let (_t, s) = fixture()?;
    std::fs::create_dir(s.root.join("run"))?;
    std::fs::set_permissions(s.root.join("run"), std::fs::Permissions::from_mode(0o700))?;
    let server = tokio::spawn(runtime::serve(s.clone()));
    for _ in 0..50 {
        if s.root.join("run/control.sock").exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let path = s.root.clone();
    let result =
        tokio::task::spawn_blocking(move || runtime::request(&path, &runtime::Request::Overview))
            .await?;
    assert!(result.is_err());
    let token = login(
        &s,
        unsafe { libc::geteuid() }.wrapping_add(1),
        "owner@fixture.invalid",
    )?;
    let request: Envelope = serde_json::from_value(
        json!({"version":1,"request_id":"peer-test","session":token,"confirmation":null,"payload":{"action":"whoami"}}),
    )?;
    let path = s.root.clone();
    assert!(
        tokio::task::spawn_blocking(move || runtime::authenticated_request(&path, &request))
            .await?
            .is_err()
    );
    server.abort();
    Ok(())
}
#[test]
fn concurrent_self_demotions_leave_one_operator_and_receipts_bind_actor() -> Result<()> {
    let (_t, s) = fixture()?;
    let a = login(&s, 81, "owner@fixture.invalid")?;
    let aid = call(&s, 81, Some(&a), json!({"action":"whoami"}), None)?["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = confirmed(
        &s,
        81,
        &a,
        json!({"action":"user_create","account":"second@fixture.invalid","password":"fixture-password-long","role":"operator","grants":{}}),
    )?;
    let bid = b["user"]["id"].as_str().unwrap().to_owned();
    let bt = login(&s, 82, "second@fixture.invalid")?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for (uid, token, id) in [(81, a, aid), (82, bt, bid)] {
        let target = json!({"action":"user_update","id":id,"expected_revision":1,"role":"viewer","grants":{},"disabled":false});
        let c = call(
            &s,
            uid,
            Some(&token),
            json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),
            None,
        )?;
        let req: Envelope = serde_json::from_value(
            json!({"version":1,"request_id":auth::random()?,"session":token,"confirmation":c["confirmation"],"payload":target}),
        )?;
        let separate = Store::open(&s.root)?;
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            roles::handle(&separate, uid, &req).is_ok()
        }));
    }
    assert_eq!(
        threads
            .into_iter()
            .filter(|t| t.thread().id() != std::thread::current().id())
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(
        db(&s)?.query_row(
            "SELECT COUNT(*) FROM users WHERE role='operator' AND disabled=0",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    let email: String =
        db(&s)?.query_row("SELECT email FROM users WHERE role='operator'", [], |r| {
            r.get(0)
        })?;
    let token = login(&s, 83, &email)?;
    let rid: String = db(&s)?.query_row(
        "SELECT request_id FROM security_receipts WHERE action='user_create'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        call(
            &s,
            83,
            Some(&token),
            json!({"action":"receipt_get","request_id":rid}),
            None
        )?["verified"],
        true
    );
    db(&s)?.execute(
        "UPDATE security_receipts SET actor='forged' WHERE request_id=?1",
        [&rid],
    )?;
    assert!(
        call(
            &s,
            83,
            Some(&token),
            json!({"action":"receipt_get","request_id":rid}),
            None
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn self_password_change_revokes_terminal_and_legacy_web_tokens() -> Result<()> {
    let (_t, s) = fixture()?;
    let terminal = login(&s, 90, "owner@fixture.invalid")?;
    let web = s.login("owner@fixture.invalid", "fixture-password-long", "legacy")?;
    call(
        &s,
        90,
        Some(&terminal),
        json!({"action":"change_password","current_password":"fixture-password-long","password":"new-fixture-password-long"}),
        None,
    )?;
    assert!(s.session(&web)?.is_none());
    assert!(call(&s, 90, Some(&terminal), json!({"action":"whoami"}), None).is_err());
    assert!(login(&s, 90, "owner@fixture.invalid").is_err());
    assert!(call(&s,90,None,json!({"action":"login","account":"owner@fixture.invalid","password":"new-fixture-password-long"}),None).is_ok());
    Ok(())
}
#[test]
fn confirmation_expiry_revision_and_successful_login_rate_are_enforced() -> Result<()> {
    let (_t, s) = fixture()?;
    let token = login(&s, 110, "owner@fixture.invalid")?;
    let target = json!({"action":"security_set","expected_revision":1,"admin_enabled":true});
    let c = call(
        &s,
        110,
        Some(&token),
        json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),
        None,
    )?;
    db(&s)?.execute("UPDATE terminal_confirmations SET expires=0", [])?;
    assert!(
        call(
            &s,
            110,
            Some(&token),
            target.clone(),
            c["confirmation"].as_str()
        )
        .is_err()
    );
    let c = call(
        &s,
        110,
        Some(&token),
        json!({"action":"reauthenticate","password":"fixture-password-long","target":target}),
        None,
    )?;
    db(&s)?.execute("UPDATE users SET auth_revision=auth_revision+1", [])?;
    assert!(call(&s, 110, Some(&token), target, c["confirmation"].as_str()).is_err());
    for _ in 0..5 {
        login(&s, 111, "owner@fixture.invalid")?;
    }
    assert!(
        login(&s, 111, "owner@fixture.invalid")
            .unwrap_err()
            .to_string()
            .contains("retry later")
    );
    let root = s.root.clone();
    drop(s);
    let s = Store::open(&root)?;
    assert!(login(&s, 111, "owner@fixture.invalid").is_err());
    db(&s)?.execute("UPDATE security_attempts SET start=?1", [auth::now() - 901])?;
    assert!(login(&s, 111, "owner@fixture.invalid").is_ok());
    Ok(())
}
#[tokio::test]
async fn web_admin_gate_is_independent_and_revokes_existing_web_sessions() -> Result<()> {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use kagnode_daemon::web::{self, App};
    use tower::ServiceExt;
    let (_t, s) = fixture()?;
    let token = login(&s, 120, "owner@fixture.invalid")?;
    let web_token = s.login(
        "owner@fixture.invalid",
        "fixture-password-long",
        "web-fixture",
    )?;
    let router = web::router(App {
        store: s.clone(),
        origin: "http://localhost".into(),
        core: std::sync::Arc::new(
            kagnode_core::Core::new(s.root.join("core"), "daemon")
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        ),
    });
    let req = || {
        Request::builder()
            .uri("/api/v1/audit")
            .header("cookie", format!("kn_daemon={web_token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        router.clone().oneshot(req()).await?.status(),
        StatusCode::FORBIDDEN
    );
    confirmed(
        &s,
        120,
        &token,
        json!({"action":"security_set","expected_revision":1,"admin_enabled":true}),
    )?;
    assert_eq!(
        router.clone().oneshot(req()).await?.status(),
        StatusCode::OK
    );
    assert!(!s.settings()?.web_enabled);
    confirmed(
        &s,
        120,
        &token,
        json!({"action":"security_set","expected_revision":2,"admin_enabled":false}),
    )?;
    assert_eq!(
        router.oneshot(req()).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}
#[test]
fn cli_rejects_public_credential_files_and_does_not_echo_invalid_fields() -> Result<()> {
    let t = tempfile::tempdir()?;
    let path = t.path().join("request");
    let sentinel = "synthetic-credential-must-not-be-echoed";
    std::fs::write(&path,json!({"version":1,"request_id":"fixture","session":null,"confirmation":null,"payload":{"action":sentinel}}).to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    let run = || -> Result<std::process::Output> {
        Ok(std::process::Command::new(env!("CARGO_BIN_EXE_kagnode"))
            .args(["user", "request"])
            .stdin(std::fs::File::open(&path)?)
            .output()?)
    };
    let r = run()?;
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("must be private"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let r = run()?;
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("Invalid authenticated request"));
    assert!(!String::from_utf8_lossy(&r.stderr).contains(sentinel));
    Ok(())
}
