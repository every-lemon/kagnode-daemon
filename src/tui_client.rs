//! Terminal client for the Daemon's authenticated local socket (roles protocol 1).
//!
//! The terminal never decides who a person is: it sends the typed request and
//! the session token, and shows the Daemon's answer. The token lives only in
//! this process's memory and is never written to disk, logs or arguments.
use crate::{
    roles::Envelope,
    runtime,
    tui_auth::{Grant, Level, NewUser, Protection, Role, UserRow, Whoami},
};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub struct Client {
    root: PathBuf,
    token: Option<Zeroizing<String>>,
    /// Only the owner of a session signs it out when dropped.
    owns: bool,
}
/// Everything the screens need to know about the signed-in person.
#[derive(Clone, Debug)]
pub struct Identity {
    pub id: String,
    pub revision: i64,
    pub who: Whoami,
    /// Global actions the Daemon says this person may attempt (`capabilities.global`).
    pub global: Vec<String>,
    pub products: Vec<String>,
}
impl Identity {
    pub fn can(&self, action: &str) -> bool {
        self.global.iter().any(|a| a == action)
    }
}
/// True when the Daemon says the session ended (idle timeout, role change, restart
/// of the person's account) and the person must sign in again.
pub fn is_signed_out(error: &anyhow::Error) -> bool {
    error.to_string().starts_with("Sign in again")
}
fn parse_role(text: &str) -> Result<Role> {
    Ok(match text {
        "operator" => Role::Operator,
        "manager" => Role::Manager,
        "viewer" => Role::Viewer,
        _ => bail!("The Daemon sent an unknown role"),
    })
}
fn parse_level(text: &str) -> Result<Level> {
    Ok(match text {
        "view" => Level::View,
        "operate" => Level::Operate,
        "manage" => Level::Manage,
        _ => bail!("The Daemon sent an unknown level"),
    })
}
fn grants_of(value: &Value) -> Result<Vec<Grant>> {
    let mut grants = Vec::new();
    for (product, level) in value.as_object().into_iter().flatten() {
        grants.push(Grant {
            product: product.clone(),
            level: parse_level(level.as_str().unwrap_or(""))?,
        });
    }
    Ok(grants)
}
pub fn identity_from(value: &Value) -> Result<Identity> {
    let user = &value["user"];
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect()
    };
    Ok(Identity {
        id: user["id"].as_str().unwrap_or_default().to_owned(),
        revision: user["auth_revision"].as_i64().unwrap_or(0),
        who: Whoami {
            account: user["account"]
                .as_str()
                .ok_or_else(|| anyhow!("The Daemon sent an incomplete identity"))?
                .to_owned(),
            role: parse_role(user["role"].as_str().unwrap_or(""))?,
            protection: if value["protection"] == "unprotected" {
                Protection::Owner
            } else {
                Protection::Protected
            },
            grants: grants_of(&user["grants"])?,
        },
        global: strings(&value["capabilities"]["global"]),
        products: value["capabilities"]["products"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p["product"].as_str().map(str::to_owned))
            .collect(),
    })
}
fn row_from(value: &Value) -> Result<UserRow> {
    Ok(UserRow {
        id: value["id"].as_str().unwrap_or_default().to_owned(),
        revision: value["auth_revision"].as_i64().unwrap_or(0),
        account: value["account"].as_str().unwrap_or_default().to_owned(),
        role: parse_role(value["role"].as_str().unwrap_or(""))?,
        disabled: value["disabled"].as_bool().unwrap_or(false),
        grants: grants_of(&value["grants"])?,
    })
}
fn grants_json(grants: &[(String, Level)]) -> Value {
    Value::Object(
        grants
            .iter()
            .map(|(p, l)| (p.clone(), json!(l.label())))
            .collect(),
    )
}
fn role_text(role: Role) -> &'static str {
    match role {
        Role::Operator => "operator",
        Role::Manager => "manager",
        Role::Viewer => "viewer",
    }
}
impl Client {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            token: None,
            owns: true,
        }
    }
    /// A read-only copy for a background thread; it never signs the session out.
    pub fn reader(&self) -> Client {
        Client {
            root: self.root.clone(),
            token: self.token.clone(),
            owns: false,
        }
    }
    pub fn signed_in(&self) -> bool {
        self.token.is_some()
    }
    fn send(&self, payload: Value, confirmation: Option<&str>) -> Result<Value> {
        let request: Envelope = serde_json::from_value(json!({
            "version": 1,
            "request_id": &crate::auth::random()?[..32],
            "session": self.token.as_ref().map(|t| t.as_str()),
            "confirmation": confirmation,
            "payload": payload,
        }))
        .map_err(|_| anyhow!("The terminal could not build this request"))?;
        runtime::authenticated_request(&self.root, &request)
    }
    fn adopt(&mut self, reply: &Value) -> Result<Identity> {
        let token = reply["token"]
            .as_str()
            .ok_or_else(|| anyhow!("The Daemon did not return a session"))?;
        self.token = Some(Zeroizing::new(token.to_owned()));
        identity_from(&reply["whoami"])
    }
    /// Owner mode only: the Daemon accepts the machine owner without a password.
    pub fn owner_session(&mut self) -> Result<Identity> {
        let reply = self.send(json!({"action": "owner_session"}), None)?;
        self.adopt(&reply)
    }
    pub fn login(&mut self, account: &str, password: &str) -> Result<Identity> {
        let reply = self.send(
            json!({"action": "login", "account": account.trim(), "password": password}),
            None,
        )?;
        self.adopt(&reply)
    }
    pub fn whoami(&self) -> Result<Identity> {
        identity_from(&self.send(json!({"action": "whoami"}), None)?)
    }
    pub fn logout(&mut self) {
        if self.token.is_some() {
            let _ = self.send(json!({"action": "logout"}), None);
        }
        self.token = None;
    }
    pub fn overview(&self) -> Result<Value> {
        self.send(json!({"action": "overview"}), None)
    }
    pub fn metrics(&self, name: &str, since: i64, until: i64) -> Result<Value> {
        self.send(
            json!({"action": "metrics", "name": name, "since": since, "until": until}),
            None,
        )
    }
    pub fn product_status(&self, product: &str) -> Result<Value> {
        self.send(
            json!({"action": "product_status", "product": product}),
            None,
        )
    }
    pub fn security(&self) -> Result<Value> {
        self.send(json!({"action": "security_get"}), None)
    }
    pub fn list_users(&self) -> Result<Vec<UserRow>> {
        self.send(json!({"action": "user_list"}), None)?["users"]
            .as_array()
            .into_iter()
            .flatten()
            .map(row_from)
            .collect()
    }
    /// Risky actions: ask for a confirmation bound to this exact payload, then send
    /// the payload with it. A timed-out mutation must never be retried blindly.
    fn confirmed(&self, payload: Value, password: &str) -> Result<Value> {
        let proof = self.send(
            json!({"action": "reauthenticate", "password": password, "target": payload}),
            None,
        )?;
        let confirmation = Zeroizing::new(
            proof["confirmation"]
                .as_str()
                .ok_or_else(|| anyhow!("The Daemon did not confirm the password"))?
                .to_owned(),
        );
        self.send(payload, Some(confirmation.as_str()))
    }
    pub fn create_user(&self, user: &NewUser, my_password: &str) -> Result<UserRow> {
        let reply = self.confirmed(
            json!({
                "action": "user_create",
                "account": user.account,
                "password": user.password.as_str(),
                "role": role_text(user.role),
                "grants": grants_json(&user.grants),
            }),
            my_password,
        )?;
        row_from(&reply["user"])
    }
    /// Changes role, grants and disabled state in one revision-checked request.
    pub fn update_user(
        &self,
        row: &UserRow,
        role: Role,
        grants: &[(String, Level)],
        disabled: bool,
        my_password: &str,
    ) -> Result<UserRow> {
        let reply = self.confirmed(
            json!({
                "action": "user_update",
                "id": row.id,
                "expected_revision": row.revision,
                "role": role_text(role),
                "grants": grants_json(grants),
                "disabled": disabled,
            }),
            my_password,
        )?;
        row_from(&reply["user"])
    }
    pub fn reset_password(
        &self,
        row: &UserRow,
        new_password: &str,
        my_password: &str,
    ) -> Result<()> {
        self.confirmed(
            json!({
                "action": "user_reset_password",
                "id": row.id,
                "expected_revision": row.revision,
                "password": new_password,
            }),
            my_password,
        )?;
        Ok(())
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        // Leaving the terminal ends this person's session; the Daemon keeps running.
        if self.owns {
            self.logout();
        }
    }
}
