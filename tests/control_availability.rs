use anyhow::Result;
use kagnode_daemon::{
    auth,
    roles::{self, Envelope},
    store::{Profile, Store},
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
fn call(s: &Store, token: Option<&str>, action: Value) -> Result<Value> {
    let e: Envelope = serde_json::from_value(
        json!({"version":1,"request_id":auth::random()?,"session":token,"confirmation":null,"payload":action}),
    )?;
    roles::handle(s, 101, &e)
}
#[test]
fn availability_is_scoped_and_never_advertises_unqualified_execution() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let s = Store::open(&dir.path().join("state"))?;
    s.init(
        "operator@fixture.invalid",
        "fixture-password-long",
        Profile::Light,
        false,
    )?;
    let db = Connection::open(s.root.join("daemon.sqlite"))?;
    for role in ["manager", "viewer"] {
        db.execute(
            "INSERT INTO users VALUES(?1,?2,?3,?1,0,0,'fixture',1)",
            params![
                role,
                format!("{role}@fixture.invalid"),
                auth::hash_password("fixture-password-long")?
            ],
        )?;
    }
    db.execute(
        "INSERT INTO user_grants VALUES('manager','mail','view')",
        [],
    )?;
    for role in ["operator", "manager", "viewer"] {
        let login = call(
            &s,
            None,
            json!({"action":"login","account":format!("{role}@fixture.invalid"),"password":"fixture-password-long"}),
        )?;
        let token = login["token"].as_str().unwrap();
        for product in ["mail", "vpn", "backup", "unknown"] {
            let result = call(
                &s,
                Some(token),
                json!({"action":"product_controls","product":product}),
            );
            if product == "unknown" || role == "viewer" || (role == "manager" && product != "mail")
            {
                assert!(result.is_err());
                continue;
            }
            let result = result?;
            assert_eq!(result["native_actions_enabled"], false);
            for control in result["controls"].as_array().unwrap() {
                assert_eq!(control["available"], false);
                assert_eq!(control["code"], "control_unavailable");
                assert!(!control["reason"].as_str().unwrap().is_empty());
                let mut target = json!({"action":control["action"],"product":product});
                assert!(serde_json::from_value::<roles::Action>(target.take()).is_err());
                assert!(
                    !login["whoami"]["capabilities"]
                        .to_string()
                        .contains(control["action"].as_str().unwrap())
                );
            }
        }
    }
    Ok(())
}
