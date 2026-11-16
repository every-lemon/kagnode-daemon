//! The terminal client against the real private socket server (same process,
//! synthetic store, test passwords only).
use anyhow::Result;
use kagnode_daemon::{
    roles,
    store::{Profile, Store},
    tui_auth::{Level, NewUser, Role},
    tui_client::{Client, is_signed_out},
};
use zeroize::Zeroizing;

const PASSWORD: &str = "fixture-password-long";

fn serve(store: Store) -> std::path::PathBuf {
    let root = store.root.clone();
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(root.join("run"))
            .unwrap();
    }
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(kagnode_daemon::runtime::serve(store))
            .ok();
    });
    for _ in 0..100 {
        if root.join("run/control.sock").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    root
}
fn protected() -> Result<(tempfile::TempDir, std::path::PathBuf)> {
    let t = tempfile::tempdir()?;
    let s = Store::open(&t.path().join("state"))?;
    s.init("boss@fixture.invalid", PASSWORD, Profile::Light, false)?;
    let root = serve(s);
    Ok((t, root))
}
fn viewer(name: &str) -> NewUser {
    NewUser {
        account: name.into(),
        password: Zeroizing::new(PASSWORD.into()),
        role: Role::Viewer,
        grants: vec![],
    }
}

#[test]
fn sign_in_whoami_and_wrong_password() -> Result<()> {
    let (_t, root) = protected()?;
    let mut c = Client::new(root);
    let err = c
        .login("boss@fixture.invalid", "wrong-password-xx")
        .unwrap_err();
    assert_eq!(err.to_string(), "Authentication refused");
    assert!(!c.signed_in());
    let me = c.login(" Boss@Fixture.invalid ", PASSWORD)?;
    assert_eq!(me.who.role, Role::Operator);
    assert!(me.can("user_create") && me.can("security_get"));
    assert_eq!(c.whoami()?.who.account, "boss@fixture.invalid");
    Ok(())
}

// The Daemon allows five sign-in/confirmation attempts per account per window
// (reported to Codex as review finding F1), so each test stays within four.
#[test]
fn operator_creates_users_with_password_confirmation() -> Result<()> {
    let (_t, root) = protected()?;
    let mut op = Client::new(root.clone());
    op.login("boss@fixture.invalid", PASSWORD)?;
    // A wrong confirmation password creates nothing.
    assert!(
        op.create_user(&viewer("v@fixture.invalid"), "not-my-password")
            .is_err()
    );
    assert_eq!(op.list_users()?.len(), 1);
    let created = op.create_user(&viewer("v@fixture.invalid"), PASSWORD)?;
    assert_eq!(created.role, Role::Viewer);
    op.create_user(
        &NewUser {
            account: "m@fixture.invalid".into(),
            password: Zeroizing::new(PASSWORD.into()),
            role: Role::Manager,
            grants: vec![("mail".into(), Level::Operate)],
        },
        PASSWORD,
    )?;
    assert_eq!(op.list_users()?.len(), 3);
    // Lower roles see only what the Daemon allows them.
    let mut v = Client::new(root.clone());
    let me = v.login("v@fixture.invalid", PASSWORD)?;
    assert!(!me.can("user_list") && me.can("overview"));
    assert!(v.list_users().is_err());
    assert!(v.overview().is_ok());
    assert!(v.product_status("mail").is_err());
    let mut m = Client::new(root);
    m.login("m@fixture.invalid", PASSWORD)?;
    assert!(m.product_status("mail").is_ok());
    assert!(m.product_status("vpn").is_err());
    Ok(())
}

#[test]
fn operator_updates_and_resets_users() -> Result<()> {
    let (_t, root) = protected()?;
    {
        let db = rusqlite::Connection::open(root.join("daemon.sqlite"))?;
        for (id, role) in [("mgr", "manager"), ("vwr", "viewer")] {
            db.execute(
                "INSERT INTO users VALUES(?1,?2,?3,?4,0,0,'synthetic-fixture',1)",
                rusqlite::params![
                    id,
                    format!("{id}@fixture.invalid"),
                    kagnode_daemon::auth::hash_password(PASSWORD)?,
                    role
                ],
            )?;
        }
        db.execute("INSERT INTO user_grants VALUES('mgr','mail','operate')", [])?;
    }
    let mut op = Client::new(root.clone());
    op.login("boss@fixture.invalid", PASSWORD)?;
    let mut m = Client::new(root.clone());
    m.login("mgr@fixture.invalid", PASSWORD)?;
    assert!(m.product_status("mail").is_ok());
    let rows = op.list_users()?;
    let row = rows
        .iter()
        .find(|r| r.account == "mgr@fixture.invalid")
        .unwrap();
    // Demote the Manager: their session ends at once; the now-stale row is refused.
    let updated = op.update_user(row, Role::Viewer, &[], false, PASSWORD)?;
    assert_eq!(updated.role, Role::Viewer);
    let gone = m.whoami().unwrap_err();
    assert!(is_signed_out(&gone), "{gone}");
    assert!(
        op.update_user(row, Role::Viewer, &[], true, PASSWORD)
            .is_err()
    );
    // Reset a password: the old one stops working.
    let row = op
        .list_users()?
        .into_iter()
        .find(|r| r.account == "vwr@fixture.invalid")
        .unwrap();
    op.reset_password(&row, "another-long-password-1", PASSWORD)?;
    assert!(
        Client::new(root.clone())
            .login("vwr@fixture.invalid", PASSWORD)
            .is_err()
    );
    Client::new(root).login("vwr@fixture.invalid", "another-long-password-1")?;
    Ok(())
}

#[test]
fn owner_mode_signs_in_without_a_password_and_cannot_manage_users() -> Result<()> {
    let t = tempfile::tempdir()?;
    let s = Store::open(&t.path().join("state"))?;
    roles::init_owner(&s, unsafe { libc::geteuid() }, Profile::Light)?;
    let root = serve(s);
    let mut c = Client::new(root);
    assert!(c.login("owner@localhost", PASSWORD).is_err());
    let me = c.owner_session()?;
    assert_eq!(
        me.who.protection,
        kagnode_daemon::tui_auth::Protection::Owner
    );
    assert!(!me.can("user_create") && me.can("enable_protection"));
    assert!(
        c.create_user(&viewer("x@fixture.invalid"), PASSWORD)
            .is_err()
    );
    Ok(())
}
