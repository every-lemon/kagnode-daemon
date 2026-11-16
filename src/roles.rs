//! Logical authorization on the private local socket. Root and the state owner
//! remain outside this boundary; do not give logical users database access.
use crate::{auth, catalog, store::Store};
use anyhow::{Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$LVpD9X5K/RWgyqzbMvnOjVApq+S+ZJ+8sAc7vPgXlZI";
pub const BACKUP_PRODUCT: &str = "backup";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Operator,
    Manager,
    Viewer,
}
impl Role {
    fn text(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Manager => "manager",
            Self::Viewer => "viewer",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    View,
    Operate,
    Manage,
}
impl Level {
    fn text(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Operate => "operate",
            Self::Manage => "manage",
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub account: String,
    pub role: Role,
    pub disabled: bool,
    pub auth_revision: i64,
    pub created_at: i64,
    pub created_by: String,
    pub grants: BTreeMap<String, Level>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub request_id: String,
    pub session: Option<String>,
    pub confirmation: Option<String>,
    pub payload: Action,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Login {
        account: String,
        password: String,
    },
    OwnerSession,
    RootRecover {
        account: String,
        password: String,
    },
    Whoami,
    Capabilities,
    Logout,
    Reauthenticate {
        password: String,
        target: Box<Action>,
    },
    UserList,
    UserCreate {
        account: String,
        password: String,
        role: Role,
        grants: BTreeMap<String, Level>,
    },
    UserUpdate {
        id: String,
        expected_revision: i64,
        role: Role,
        grants: BTreeMap<String, Level>,
        disabled: bool,
    },
    UserResetPassword {
        id: String,
        expected_revision: i64,
        password: String,
    },
    ChangePassword {
        current_password: String,
        password: String,
    },
    EnableProtection {
        account: String,
        password: String,
    },
    SecurityGet,
    SecuritySet {
        expected_revision: i64,
        admin_enabled: bool,
    },
    Overview,
    Metrics {
        name: String,
        since: i64,
        until: i64,
    },
    Retention,
    SetRetention {
        revision: i64,
        policy: crate::metrics::Policy,
        confirm_trim: bool,
    },
    ProductStatus {
        product: String,
    },
    BackupAgentStatus,
    Audit,
    ReceiptGet {
        request_id: String,
    },
}
impl Drop for Action {
    fn drop(&mut self) {
        match self {
            Self::Login { password, .. }
            | Self::RootRecover { password, .. }
            | Self::Reauthenticate { password, .. }
            | Self::UserCreate { password, .. }
            | Self::UserResetPassword { password, .. }
            | Self::EnableProtection { password, .. } => password.zeroize(),
            Self::ChangePassword {
                current_password,
                password,
            } => {
                current_password.zeroize();
                password.zeroize();
            }
            _ => {}
        }
    }
}
impl Drop for Envelope {
    fn drop(&mut self) {
        self.session.zeroize();
        self.confirmation.zeroize();
    }
}
impl Action {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Login { .. } => "login",
            Self::OwnerSession => "owner_session",
            Self::RootRecover { .. } => "root_recover",
            Self::Whoami => "whoami",
            Self::Capabilities => "capabilities",
            Self::Logout => "logout",
            Self::Reauthenticate { .. } => "reauthenticate",
            Self::UserList => "user_list",
            Self::UserCreate { .. } => "user_create",
            Self::UserUpdate { .. } => "user_update",
            Self::UserResetPassword { .. } => "user_reset_password",
            Self::ChangePassword { .. } => "change_password",
            Self::EnableProtection { .. } => "enable_protection",
            Self::SecurityGet => "security_get",
            Self::SecuritySet { .. } => "security_set",
            Self::Overview => "overview",
            Self::Metrics { .. } => "metrics",
            Self::Retention => "retention",
            Self::SetRetention { .. } => "set_retention",
            Self::ProductStatus { .. } => "product_status",
            Self::BackupAgentStatus => "backup_agent_status",
            Self::Audit => "audit",
            Self::ReceiptGet { .. } => "receipt_get",
        }
    }
    fn risky(&self) -> bool {
        matches!(
            self,
            Self::UserCreate { .. }
                | Self::UserUpdate { .. }
                | Self::UserResetPassword { .. }
                | Self::SecuritySet { .. }
                | Self::SetRetention { .. }
        )
    }
    fn scope(&self) -> Option<&str> {
        match self {
            Self::ProductStatus { product } => Some(product),
            Self::BackupAgentStatus => Some(BACKUP_PRODUCT),
            _ => None,
        }
    }
}
pub fn valid_product(p: &str) -> bool {
    p == BACKUP_PRODUCT || catalog::PRODUCTS.iter().any(|x| x.id == p)
}
fn grants(role: Role, values: &BTreeMap<String, Level>) -> Result<()> {
    ensure!(
        role == Role::Manager || values.is_empty(),
        "Only Managers have product grants"
    );
    ensure!(values.keys().all(|p| valid_product(p)), "Unknown product");
    Ok(())
}
/// Fixed intent permission matrix. An allowed intent is not an implemented native
/// operation; socket handlers and capabilities expose only implemented actions.
pub fn permits(p: &Principal, action: &str, product: Option<&str>) -> bool {
    if p.disabled {
        return false;
    }
    let level = match action {
        "product_status" | "core_status" | "backup_read" => Some(Level::View),
        "logs" | "backup_pin" => Some(Level::Operate),
        "boot_set" | "core_plan" | "core_apply" | "core_rollback" | "core_policy"
        | "backup_manage" => Some(Level::Manage),
        "overview" | "metrics" | "retention" | "whoami" | "capabilities" | "logout"
        | "change_password" => return product.is_none(),
        "user_list"
        | "user_create"
        | "user_update"
        | "user_reset_password"
        | "security_get"
        | "security_set"
        | "audit"
        | "receipt_get"
        | "enable_protection"
        | "global_manage"
        | "set_retention" => return product.is_none() && p.role == Role::Operator,
        _ => return false,
    };
    let Some(product) = product.filter(|p| valid_product(p)) else {
        return false;
    };
    if action.starts_with("backup_") && product != BACKUP_PRODUCT {
        return false;
    }
    p.role == Role::Operator
        || (p.role == Role::Manager && p.grants.get(product).is_some_and(|v| Some(*v) >= level))
}
fn allowed(p: &Principal, a: &Action) -> bool {
    let action = if matches!(a, Action::SetRetention { .. }) {
        "global_manage"
    } else if matches!(a, Action::BackupAgentStatus) {
        "backup_read"
    } else {
        a.name()
    };
    permits(p, action, a.scope())
}
pub(crate) fn migrate(db: &mut Connection, owner_uid: u32) -> Result<()> {
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS security_config(id INTEGER PRIMARY KEY CHECK(id=1),mode TEXT NOT NULL CHECK(mode IN ('protected','owner')),owner_uid INTEGER NOT NULL,owner_id TEXT,admin_enabled INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,password_hash TEXT,role TEXT NOT NULL CHECK(role IN ('operator','manager','viewer')),disabled INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,created_by TEXT NOT NULL,auth_revision INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS user_grants(user_id TEXT NOT NULL REFERENCES users(id),product TEXT NOT NULL,level TEXT NOT NULL,PRIMARY KEY(user_id,product));
CREATE TABLE IF NOT EXISTS terminal_sessions(hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),uid INTEGER NOT NULL,auth_revision INTEGER NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,last_use INTEGER NOT NULL,authenticated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS terminal_confirmations(hash TEXT PRIMARY KEY,session_hash TEXT NOT NULL,auth_revision INTEGER NOT NULL,request_hash TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS security_attempts(identity TEXT PRIMARY KEY,start INTEGER NOT NULL,count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS security_receipts(request_id TEXT PRIMARY KEY,actor TEXT NOT NULL,uid INTEGER NOT NULL,mode TEXT NOT NULL,action TEXT NOT NULL,request_hash TEXT NOT NULL,outcome TEXT NOT NULL,at INTEGER NOT NULL,receipt_mac TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS security_key(id INTEGER PRIMARY KEY CHECK(id=1),key_hex TEXT NOT NULL);")?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS web_session_revisions(session_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,auth_revision INTEGER NOT NULL);")?;
    tx.execute(
        "INSERT OR IGNORE INTO security_key VALUES(1,?1)",
        [auth::random()?],
    )?;
    let fresh = tx.execute(
        "INSERT OR IGNORE INTO security_config VALUES(1,'protected',?1,NULL,0,1)",
        [owner_uid],
    )?;
    if fresh == 1 {
        let old = {
            let mut q = tx.prepare("SELECT email,password_hash FROM admins")?;
            q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (email, hash) in old {
            tx.execute(
                "INSERT INTO users VALUES(?1,?2,?3,'operator',0,?4,'migration',1)",
                params![auth::random()?, email, hash, auth::now()],
            )?;
        }
        tx.execute_batch("DELETE FROM backup_confirmations; DELETE FROM sessions;")?;
        audit(
            &tx,
            "migration",
            owner_uid,
            "protected",
            "migration",
            "",
            "accepted",
        )?;
    }
    tx.commit()?;
    Ok(())
}
pub(crate) fn initialized_user(db: &Connection, email: &str, hash: &str) -> Result<()> {
    ensure!(
        db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))? == 0,
        "Existing users retained"
    );
    db.execute(
        "INSERT INTO users VALUES(?1,?2,?3,'operator',0,?4,'initialization',1)",
        params![auth::random()?, email, hash, auth::now()],
    )?;
    Ok(())
}
fn principal(db: &Connection, id: &str) -> Result<Principal> {
    let mut p = db.query_row(
        "SELECT id,email,role,disabled,auth_revision,created_at,created_by FROM users WHERE id=?1",
        [id],
        |r| {
            Ok(Principal {
                id: r.get(0)?,
                account: r.get(1)?,
                role: Role::Viewer,
                disabled: r.get::<_, i64>(3)? != 0,
                auth_revision: r.get(4)?,
                created_at: r.get(5)?,
                created_by: r.get(6)?,
                grants: BTreeMap::new(),
            })
        },
    )?;
    let role: String = db.query_row("SELECT role FROM users WHERE id=?1", [id], |r| r.get(0))?;
    p.role = serde_json::from_value(json!(role))?;
    let mut q = db.prepare("SELECT product,level FROM user_grants WHERE user_id=?1")?;
    for item in q.query_map([id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (k, v) = item?;
        p.grants.insert(k, serde_json::from_value(json!(v))?);
    }
    Ok(p)
}
fn mode(db: &Connection) -> Result<String> {
    Ok(
        db.query_row("SELECT mode FROM security_config WHERE id=1", [], |r| {
            r.get(0)
        })?,
    )
}
fn audit(
    db: &Connection,
    actor: &str,
    uid: u32,
    mode: &str,
    action: &str,
    request_id: &str,
    outcome: &str,
) -> Result<()> {
    let account = db
        .query_row("SELECT email FROM users WHERE id=?1", [actor], |r| {
            r.get::<_, String>(0)
        })
        .optional()?;
    db.execute(
        "INSERT INTO audit(at,actor,action,detail) VALUES(?1,?2,?3,?4)",
        params![
            auth::now(),
            actor,
            format!("security:{action}"),
            json!({"account":account,"uid":uid,"mode":mode,"request_id":request_id,"outcome":outcome}).to_string()
        ],
    )?;
    Ok(())
}
fn rate(db: &Connection, uid: u32, account: &str) -> Result<()> {
    let now = auth::now();
    db.execute("DELETE FROM security_attempts WHERE start<=?1", [now - 900])?;
    // Charge broad buckets before inserting attacker-controlled identity keys.
    for (key, limit) in [
        ("global".to_owned(), 200),
        (format!("uid:{uid}"), 50),
        (format!("id:{uid}:{}", auth::digest(account)), 5),
    ] {
        db.execute("INSERT INTO security_attempts VALUES(?1,?2,1) ON CONFLICT(identity) DO UPDATE SET count=count+1",params![key,now])?;
        ensure!(
            db.query_row(
                "SELECT count FROM security_attempts WHERE identity=?1",
                [key],
                |r| r.get::<_, i64>(0)
            )? <= limit,
            "Authentication refused; retry later"
        );
    }
    Ok(())
}
fn invalidate(db: &Connection, id: &str) -> Result<()> {
    db.execute("DELETE FROM terminal_confirmations WHERE session_hash IN (SELECT hash FROM terminal_sessions WHERE user_id=?1)",[id])?;
    db.execute("DELETE FROM terminal_sessions WHERE user_id=?1", [id])?;
    db.execute("DELETE FROM backup_confirmations WHERE session_hash IN (SELECT token_hash FROM sessions WHERE email=(SELECT email FROM users WHERE id=?1))",[id])?;
    db.execute(
        "DELETE FROM sessions WHERE email=(SELECT email FROM users WHERE id=?1)",
        [id],
    )?;
    Ok(())
}
fn mirror_admin(db: &Connection, id: &str) -> Result<()> {
    let p = principal(db, id)?;
    db.execute("DELETE FROM admins WHERE email=?1", [&p.account])?;
    if p.role == Role::Operator && !p.disabled {
        db.execute("INSERT INTO admins SELECT email,password_hash FROM users WHERE id=?1 AND password_hash IS NOT NULL",[id])?;
    }
    Ok(())
}
fn identify(db: &Connection, uid: u32, token: &str) -> Result<Principal> {
    ensure!(token.len() == 64, "Sign in again");
    let now = auth::now();
    let (id,revision):(String,i64)=db.query_row("SELECT user_id,auth_revision FROM terminal_sessions WHERE hash=?1 AND uid=?2 AND expires>?3 AND last_use>?4",params![auth::digest(token),uid,now,now-900],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|anyhow::anyhow!("Sign in again"))?;
    let p = principal(db, &id)?;
    ensure!(!p.disabled && p.auth_revision == revision, "Sign in again");
    db.execute(
        "UPDATE terminal_sessions SET last_use=?2 WHERE hash=?1",
        params![auth::digest(token), now],
    )?;
    Ok(p)
}
fn session(db: &Connection, p: &Principal, uid: u32) -> Result<Value> {
    let now = auth::now();
    let token = auth::random()?;
    db.execute(
        "DELETE FROM terminal_confirmations WHERE expires<=?1",
        [now],
    )?;
    db.execute(
        "DELETE FROM terminal_sessions WHERE expires<=?1 OR last_use<=?2",
        params![now, now - 900],
    )?;
    ensure!(
        db.query_row(
            "SELECT COUNT(*) FROM terminal_sessions WHERE user_id=?1",
            [&p.id],
            |r| r.get::<_, i64>(0)
        )? < 16,
        "Session limit reached"
    );
    db.execute(
        "INSERT INTO terminal_sessions VALUES(?1,?2,?3,?4,?5,?6,?5,?5)",
        params![
            auth::digest(&token),
            p.id,
            uid,
            p.auth_revision,
            now,
            now + 28800
        ],
    )?;
    Ok(json!({"token":token,"expires_at":now+28800,"whoami":whoami(db,p)?}))
}
fn capabilities(p: &Principal, m: &str) -> Value {
    let global = [
        "whoami",
        "capabilities",
        "logout",
        "change_password",
        "overview",
        "metrics",
        "retention",
        "set_retention",
        "user_list",
        "user_create",
        "user_update",
        "user_reset_password",
        "security_get",
        "security_set",
        "audit",
        "receipt_get",
        "enable_protection",
    ]
    .into_iter()
    .filter(|a| {
        permits(p, a, None)
            && (m == "owner" || *a != "enable_protection")
            && (m != "owner"
                || !matches!(
                    *a,
                    "user_create"
                        | "user_update"
                        | "user_reset_password"
                        | "security_set"
                        | "change_password"
                        | "set_retention"
                ))
    })
    .collect::<Vec<_>>();
    let products = catalog::PRODUCTS
        .iter()
        .filter(|x| permits(p, "product_status", Some(x.id)))
        .map(|x| json!({"product":x.id,"actions":["product_status"]}))
        .collect::<Vec<_>>();
    json!({"global":global,"products":products,"backup_agent_status":permits(p,"backup_read",Some(BACKUP_PRODUCT)),"native_actions_enabled":false})
}
fn whoami(db: &Connection, p: &Principal) -> Result<Value> {
    let m = mode(db)?;
    Ok(
        json!({"user":p,"protection":if m=="owner"{"unprotected"}else{"protected"},"implicit_operator":m=="owner","capabilities":capabilities(p,&m)}),
    )
}
fn mac(db: &Connection, bytes: &[u8]) -> Result<String> {
    let key = Zeroizing::new(db.query_row(
        "SELECT key_hex FROM security_key WHERE id=1",
        [],
        |r| r.get::<_, String>(0),
    )?);
    let key = Zeroizing::new(hex::decode(key.as_str())?);
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    Ok(hex::encode(ring::hmac::sign(&key, bytes).as_ref()))
}
fn digest(db: &Connection, a: &Action) -> Result<String> {
    let encoded = Zeroizing::new(serde_json::to_string(a)?);
    mac(db, encoded.as_bytes())
}

pub fn handle(store: &Store, uid: u32, e: &Envelope) -> Result<Value> {
    ensure!(
        e.version == 1
            && (1..=64).contains(&e.request_id.len())
            && e.request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "Invalid request envelope"
    );
    let mut db = store.db()?;
    let m = mode(&db)?;
    let actor = e
        .session
        .as_deref()
        .and_then(|s| identify(&db, uid, s).ok())
        .map(|p| p.id)
        .unwrap_or_else(|| {
            if matches!(e.payload, Action::RootRecover { .. }) {
                "root-recovery".into()
            } else {
                "unauthenticated".into()
            }
        });
    let action = e.payload.name();
    let result = execute(&mut db, uid, e, &m);
    // Audit refused authentication/authorization too, without echoing identities,
    // request bodies, passwords, tokens or arbitrary error strings.
    if result.is_err() {
        audit(&db, &actor, uid, &m, action, &e.request_id, "refused")?;
    }
    result
}
fn execute(db: &mut Connection, uid: u32, e: &Envelope, m: &str) -> Result<Value> {
    match &e.payload {
        Action::Login { account, password } => {
            ensure!(
                e.session.is_none() && e.confirmation.is_none() && m == "protected",
                "Authentication refused"
            );
            let account = auth::email(account).unwrap_or_default();
            rate(db, uid, &account)?;
            let row = db
                .query_row(
                    "SELECT id,password_hash FROM users WHERE email=?1 AND disabled=0",
                    [&account],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
                )
                .optional()?;
            let valid = auth::verify(
                password,
                row.as_ref().and_then(|r| r.1.as_deref()).unwrap_or(DUMMY),
            );
            ensure!(valid && row.is_some(), "Authentication refused");
            let (id, verified_hash) = row.unwrap();
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let current: Option<String> = tx
                .query_row(
                    "SELECT password_hash FROM users WHERE id=?1 AND disabled=0",
                    [&id],
                    |r| r.get(0),
                )
                .map_err(|_| anyhow::anyhow!("Authentication refused"))?;
            ensure!(current == verified_hash, "Authentication refused");
            let p = principal(&tx, &id)?;
            let result = session(&tx, &p, uid)?;
            audit(&tx, &p.id, uid, m, "login", &e.request_id, "accepted")?;
            tx.commit()?;
            return Ok(result);
        }
        Action::OwnerSession => {
            let (owner, id): (u32, Option<String>) = db.query_row(
                "SELECT owner_uid,owner_id FROM security_config WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                m == "owner" && uid == owner && e.session.is_none() && e.confirmation.is_none(),
                "Owner mode refused"
            );
            let p = principal(
                db,
                &id.ok_or_else(|| anyhow::anyhow!("Owner not configured"))?,
            )?;
            audit(
                db,
                &p.id,
                uid,
                m,
                "owner_session",
                &e.request_id,
                "accepted",
            )?;
            return session(db, &p, uid);
        }
        Action::RootRecover { account, password } => {
            ensure!(
                uid == 0 && e.session.is_none() && e.confirmation.is_none(),
                "Root recovery requires root peer credentials"
            );
            let account = auth::email(account)?;
            let hash = auth::hash_password(password)?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let id = tx
                .query_row("SELECT id FROM users WHERE email=?1", [&account], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .unwrap_or(auth::random()?);
            tx.execute("INSERT INTO users VALUES(?1,?2,?3,'operator',0,?4,'root-recovery',1) ON CONFLICT(email) DO UPDATE SET password_hash=excluded.password_hash,role='operator',disabled=0,auth_revision=auth_revision+1",params![id,account,hash,auth::now()])?;
            // Recovery never leaves an implicit passwordless identity active.
            if m == "owner" {
                tx.execute("UPDATE users SET disabled=1,auth_revision=auth_revision+1 WHERE id=(SELECT owner_id FROM security_config) AND id!=?1",[&id])?;
                tx.execute_batch(
                    "DELETE FROM terminal_confirmations; DELETE FROM terminal_sessions;",
                )?;
            }
            invalidate(&tx, &id)?;
            tx.execute("DELETE FROM user_grants WHERE user_id=?1", [&id])?;
            mirror_admin(&tx, &id)?;
            tx.execute("UPDATE security_config SET mode='protected',owner_id=NULL,revision=revision+1 WHERE id=1",[])?;
            receipt(&tx, "root-recovery", uid, m, e)?;
            tx.commit()?;
            return Ok(json!({"recovered":true,"fresh_login_required":true}));
        }
        _ => {}
    }
    let token = e
        .session
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Sign in again"))?;
    let p = identify(db, uid, token)?;
    if let Action::Reauthenticate { password, target } = &e.payload {
        ensure!(
            allowed(&p, target) && target.risky() && m == "protected" && e.confirmation.is_none(),
            "Confirmation refused"
        );
        rate(db, uid, &p.account)?;
        let hash: Option<String> = db.query_row(
            "SELECT password_hash FROM users WHERE id=?1",
            [&p.id],
            |r| r.get(0),
        )?;
        ensure!(
            auth::verify(password, hash.as_deref().unwrap_or(DUMMY)),
            "Authentication refused"
        );
        let confirmation = auth::random()?;
        db.execute(
            "DELETE FROM terminal_confirmations WHERE session_hash=?1 OR expires<=?2",
            params![auth::digest(token), auth::now()],
        )?;
        db.execute(
            "INSERT INTO terminal_confirmations VALUES(?1,?2,?3,?4,?5)",
            params![
                auth::digest(&confirmation),
                auth::digest(token),
                p.auth_revision,
                digest(db, target)?,
                auth::now() + 90
            ],
        )?;
        db.execute(
            "UPDATE terminal_sessions SET authenticated_at=?2 WHERE hash=?1",
            params![auth::digest(token), auth::now()],
        )?;
        audit(
            db,
            &p.id,
            uid,
            m,
            "reauthenticate",
            &e.request_id,
            "accepted",
        )?;
        return Ok(json!({"confirmation":confirmation,"expires_in":90}));
    }
    ensure!(allowed(&p, &e.payload), "Action not permitted");
    if matches!(e.payload, Action::ChangePassword { .. }) {
        rate(db, uid, &p.account)?;
    }
    if e.payload.risky() {
        ensure!(m == "protected", "Enable password protection first");
        let confirmation = e.confirmation.as_deref().unwrap_or("");
        ensure!(db.execute("DELETE FROM terminal_confirmations WHERE hash=?1 AND session_hash=?2 AND auth_revision=?3 AND request_hash=?4 AND expires>?5 AND EXISTS(SELECT 1 FROM terminal_sessions WHERE hash=?2 AND authenticated_at>?6)",params![auth::digest(confirmation),auth::digest(token),p.auth_revision,digest(db,&e.payload)?,auth::now(),auth::now()-300])?==1,"Fresh confirmation required");
        // Consume before the mutation transaction: a failed/uncertain attempt must
        // not leave its old confirmation reusable.
    } else {
        ensure!(e.confirmation.is_none(), "Unexpected confirmation");
    }
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let p = identify(&tx, uid, token)?;
    ensure!(allowed(&p, &e.payload), "Action not permitted");
    let value = match &e.payload {
        Action::Whoami => whoami(&tx, &p)?,
        Action::Capabilities => capabilities(&p, m),
        Action::Logout => {
            tx.execute(
                "DELETE FROM terminal_confirmations WHERE session_hash=?1",
                [auth::digest(token)],
            )?;
            tx.execute(
                "DELETE FROM terminal_sessions WHERE hash=?1",
                [auth::digest(token)],
            )?;
            json!({"signed_out":true})
        }
        Action::SecurityGet => security(&tx)?,
        Action::UserList => {
            let ids = {
                let mut q = tx.prepare("SELECT id FROM users ORDER BY email LIMIT 1000")?;
                q.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            json!({"users":ids.iter().map(|id|principal(&tx,id)).collect::<Result<Vec<_>>>()?})
        }
        Action::UserCreate {
            account,
            password,
            role,
            grants: gs,
        } => {
            grants(*role, gs)?;
            let account = auth::email(account)?;
            let hash = Zeroizing::new(auth::hash_password(password)?);
            let id = auth::random()?;
            ensure!(
                tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))? < 1000,
                "User limit reached"
            );
            tx.execute(
                "INSERT INTO users VALUES(?1,?2,?3,?4,0,?5,?6,1)",
                params![id, account, hash.as_str(), role.text(), auth::now(), p.id],
            )?;
            set_grants(&tx, &id, gs)?;
            mirror_admin(&tx, &id)?;
            json!({"user":principal(&tx,&id)?})
        }
        Action::UserUpdate {
            id,
            expected_revision,
            role,
            grants: gs,
            disabled,
        } => {
            grants(*role, gs)?;
            let old = principal(&tx, id)?;
            ensure!(
                old.auth_revision == *expected_revision,
                "User changed; reload"
            );
            if old.role == Role::Operator && !old.disabled && (*role != Role::Operator || *disabled)
            {
                ensure!(
                    tx.query_row(
                        "SELECT COUNT(*) FROM users WHERE role='operator' AND disabled=0",
                        [],
                        |r| r.get::<_, i64>(0)
                    )? > 1,
                    "Cannot remove the last enabled Operator"
                );
            }
            invalidate(&tx, id)?;
            tx.execute(
                "UPDATE users SET role=?2,disabled=?3,auth_revision=auth_revision+1 WHERE id=?1",
                params![id, role.text(), disabled],
            )?;
            set_grants(&tx, id, gs)?;
            mirror_admin(&tx, id)?;
            json!({"user":principal(&tx,id)?})
        }
        Action::UserResetPassword {
            id,
            expected_revision,
            password,
        } => {
            let old = principal(&tx, id)?;
            ensure!(
                old.auth_revision == *expected_revision,
                "User changed; reload"
            );
            password_change(&tx, id, password)?;
            json!({"fresh_login_required":true})
        }
        Action::ChangePassword {
            current_password,
            password,
        } => {
            ensure!(m == "protected", "Use enable_protection in owner mode");
            let hash: Option<String> = tx.query_row(
                "SELECT password_hash FROM users WHERE id=?1",
                [&p.id],
                |r| r.get(0),
            )?;
            ensure!(
                auth::verify(current_password, hash.as_deref().unwrap_or(DUMMY)),
                "Authentication refused"
            );
            password_change(&tx, &p.id, password)?;
            json!({"fresh_login_required":true})
        }
        Action::EnableProtection { account, password } => {
            let (owner, id): (u32, Option<String>) =
                tx.query_row("SELECT owner_uid,owner_id FROM security_config", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            ensure!(
                m == "owner" && owner == uid && id.as_deref() == Some(&p.id),
                "Owner transition refused"
            );
            let account = auth::email(account)?;
            invalidate(&tx, &p.id)?;
            tx.execute(
                "UPDATE users SET email=?2 WHERE id=?1",
                params![p.id, account],
            )?;
            password_change(&tx, &p.id, password)?;
            tx.execute("UPDATE security_config SET mode='protected',owner_id=NULL,revision=revision+1 WHERE id=1",[])?;
            json!({"protection":"protected","fresh_login_required":true})
        }
        Action::SecuritySet {
            expected_revision,
            admin_enabled,
        } => {
            ensure!(tx.execute("UPDATE security_config SET admin_enabled=?1,revision=revision+1 WHERE id=1 AND revision=?2",params![admin_enabled,expected_revision])?==1,"Security settings changed; reload");
            if !admin_enabled {
                tx.execute_batch("DELETE FROM backup_confirmations; DELETE FROM sessions;")?;
            }
            security(&tx)?
        }
        Action::Audit => {
            let mut q =
                tx.prepare("SELECT at,actor,action,detail FROM audit ORDER BY id DESC LIMIT 100")?;
            json!({"events":q.query_map([],|r|Ok(json!({"at":r.get::<_,i64>(0)?,"actor":r.get::<_,String>(1)?,"action":r.get::<_,String>(2)?,"detail":r.get::<_,String>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?})
        }
        Action::ReceiptGet { request_id } => {
            let record=tx.query_row("SELECT actor,uid,mode,action,request_hash,outcome,at,receipt_mac FROM security_receipts WHERE request_id=?1",[request_id],|r|Ok((json!({"request_id":request_id,"actor":r.get::<_,String>(0)?,"uid":r.get::<_,u32>(1)?,"mode":r.get::<_,String>(2)?,"action":r.get::<_,String>(3)?,"request_hash":r.get::<_,String>(4)?,"outcome":r.get::<_,String>(5)?,"at":r.get::<_,i64>(6)?}),r.get::<_,String>(7)?)))?;
            ensure!(
                mac(&tx, record.0.to_string().as_bytes())? == record.1,
                "Receipt integrity check failed"
            );
            json!({"receipt":record.0,"mac":record.1,"verified":true})
        }
        Action::ProductStatus { product } => {
            let item = catalog::product(product)
                .ok_or_else(|| anyhow::anyhow!("No application adapter for this product"))?;
            json!({"id":item.id,"name":item.name,"native_actions_enabled":false})
        }
        Action::BackupAgentStatus => {
            let row = tx
                .query_row(
                    "SELECT revision,value FROM documents WHERE kind='backup-agent-status'",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            match row {
                Some((r, v)) => {
                    json!({"revision":r,"status":serde_json::from_str::<Value>(&v)?,"production_qualified":false})
                }
                None => {
                    json!({"revision":0,"status":{"state":"not_observed"},"production_qualified":false})
                }
            }
        }
        Action::SetRetention {
            revision,
            policy,
            confirm_trim,
        } => {
            policy.validate()?;
            let current = tx
                .query_row(
                    "SELECT revision,value FROM documents WHERE kind='monitoring'",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            let (old_revision, old) = match current {
                Some((r, v)) => (r, serde_json::from_str::<crate::metrics::Policy>(&v)?),
                None => (0, crate::metrics::Policy::default()),
            };
            ensure!(*revision == old_revision, "Retention changed; reload");
            ensure!(
                *confirm_trim
                    || (policy.days >= old.days && policy.budget_bytes >= old.budget_bytes),
                "Reducing retention requires explicit trim confirmation"
            );
            tx.execute("INSERT INTO documents VALUES('monitoring',?1,?2) ON CONFLICT(kind) DO UPDATE SET revision=excluded.revision,value=excluded.value",params![old_revision+1,serde_json::to_string(policy)?])?;
            json!({"saved":true,"revision":old_revision+1})
        }
        // Analytics are filled after dropping the DB guard in the transport layer.
        Action::Overview | Action::Metrics { .. } | Action::Retention => {
            json!({"authorized_analytics":true})
        }
        _ => bail!("Unsupported action"),
    };
    if matches!(
        e.payload,
        Action::UserCreate { .. }
            | Action::UserUpdate { .. }
            | Action::UserResetPassword { .. }
            | Action::ChangePassword { .. }
            | Action::EnableProtection { .. }
            | Action::SecuritySet { .. }
            | Action::Logout
            | Action::SetRetention { .. }
    ) {
        receipt(&tx, &p.id, uid, m, e)?;
    } else {
        audit(
            &tx,
            &p.id,
            uid,
            m,
            e.payload.name(),
            &e.request_id,
            "accepted",
        )?;
    }
    tx.commit()?;
    Ok(value)
}
fn password_change(db: &Connection, id: &str, password: &str) -> Result<()> {
    let hash = Zeroizing::new(auth::hash_password(password)?);
    invalidate(db, id)?;
    db.execute(
        "UPDATE users SET password_hash=?2,auth_revision=auth_revision+1 WHERE id=?1",
        params![id, hash.as_str()],
    )?;
    mirror_admin(db, id)?;
    Ok(())
}
fn set_grants(db: &Connection, id: &str, g: &BTreeMap<String, Level>) -> Result<()> {
    db.execute("DELETE FROM user_grants WHERE user_id=?1", [id])?;
    for (k, v) in g {
        db.execute(
            "INSERT INTO user_grants VALUES(?1,?2,?3)",
            params![id, k, v.text()],
        )?;
    }
    Ok(())
}
fn receipt(db: &Connection, id: &str, uid: u32, m: &str, e: &Envelope) -> Result<()> {
    let at = auth::now();
    let request_hash = digest(db, &e.payload)?;
    let receipt_mac=mac(db,json!({"request_id":e.request_id,"actor":id,"uid":uid,"mode":m,"action":e.payload.name(),"request_hash":request_hash,"outcome":"accepted","at":at}).to_string().as_bytes())?;
    db.execute(
        "INSERT INTO security_receipts VALUES(?1,?2,?3,?4,?5,?6,'accepted',?7,?8)",
        params![
            e.request_id,
            id,
            uid,
            m,
            e.payload.name(),
            request_hash,
            at,
            receipt_mac
        ],
    )?;
    audit(db, id, uid, m, e.payload.name(), &e.request_id, "accepted")
}
fn security(db: &Connection) -> Result<Value> {
    Ok(db.query_row("SELECT mode,owner_uid,admin_enabled,revision FROM security_config",[],|r|Ok(json!({"mode":r.get::<_,String>(0)?,"owner_uid":r.get::<_,u32>(1)?,"admin_enabled":r.get::<_,bool>(2)?,"revision":r.get::<_,i64>(3)?})))?)
}

pub fn init_owner(store: &Store, uid: u32, profile: crate::store::Profile) -> Result<()> {
    ensure!(
        uid == unsafe { libc::geteuid() },
        "Owner mode records the actual initializing uid"
    );
    let mut db = store.db()?;
    let tx = db.transaction()?;
    ensure!(
        tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))? == 0
            && tx.query_row("SELECT COUNT(*) FROM settings", [], |r| r.get::<_, i64>(0))? == 0,
        "Existing installation retained"
    );
    let id = auth::random()?;
    tx.execute("INSERT INTO users VALUES(?1,'owner@localhost',NULL,'operator',0,?2,'owner-initialization',1)",params![id,auth::now()])?;
    tx.execute("UPDATE security_config SET mode='owner',owner_uid=?1,owner_id=?2,admin_enabled=0,revision=revision+1",params![uid,id])?;
    tx.execute(
        "INSERT INTO settings VALUES(1,?1)",
        [serde_json::to_string(&crate::store::Settings {
            revision: 1,
            profile,
            web_enabled: false,
            offloading: false,
        })?],
    )?;
    audit(&tx, &id, uid, "owner", "initialize", "", "accepted")?;
    tx.commit()?;
    Ok(())
}
