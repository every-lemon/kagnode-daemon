//! Private terminal API and collectors survive the lifetime of every TUI.
use crate::{
    auth,
    metrics::{Collector, History, Policy},
    store::Store,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Overview,
    Metrics {
        name: String,
        since: i64,
        until: i64,
    },
    Retention,
    SetRetention {
        revision: i64,
        policy: Policy,
        confirm_trim: bool,
    },
}
pub fn policy(store: &Store) -> Result<(i64, Policy)> {
    match store.document("monitoring")? {
        Some((r, v)) => Ok((r, serde_json::from_value(v)?)),
        None => Ok((0, Policy::default())),
    }
}
pub fn dispatch(store: &Store, request: Request) -> Result<Value> {
    dispatch_as(store, request, "local-terminal")
}
pub fn dispatch_as(store: &Store, request: Request, actor: &str) -> Result<Value> {
    match request {
        Request::Retention => {
            let (r, p) = policy(store)?;
            Ok(json!({"revision":r,"policy":p,"presets_days":[2,5,7,30,90,180,365]}))
        }
        Request::SetRetention {
            revision,
            policy: next,
            confirm_trim,
        } => {
            next.validate()?;
            let (_, old) = policy(store)?;
            ensure!(
                confirm_trim || (next.days >= old.days && next.budget_bytes >= old.budget_bytes),
                "Reducing retention or budget requires confirmation"
            );
            store.save_document(actor, "monitoring", revision, &serde_json::to_value(&next)?)?;
            Ok(json!({"saved":true,"revision":revision+1}))
        }
        Request::Metrics { name, since, until } => Ok(
            json!({"node":"local","metric":name,"points":History::open(&store.root)?.query(&name,since,until,600)?}),
        ),
        Request::Overview => {
            let h = History::open(&store.root)?;
            let latest = h.latest()?;
            let stale = latest.as_ref().is_none_or(|v| {
                !(0..=30).contains(&(auth::now() - v.at))
                    || v.boot_id.is_empty()
                    || v.values.get("memory.total").is_none_or(|n| *n <= 0.0)
            });
            let node = json!({"id":"local","name":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_else(|_|"Local node".into()).trim(),"health":if stale{"unknown"}else{"online"},"last_sample":latest,"history_trim_events":h.health()?});
            Ok(
                json!({"nodes":[node],"profile":store.settings()?.profile,"web_enabled":store.settings()?.web_enabled,"applications":crate::catalog::PRODUCTS.iter().map(|p|json!({"id":p.id,"name":p.name,"installed":crate::catalog::installed(store.managed_root(),p)})).collect::<Vec<_>>(),"audit":store.audit()?}),
            )
        }
    }
}
pub fn request(root: &Path, value: &Request) -> Result<Value> {
    // Compatibility client only. The server rejects this unauthenticated legacy
    // shape; terminal presentation must adopt roles::Envelope before release.
    wire_request(root, value)
}
pub fn authenticated_request(root: &Path, value: &crate::roles::Envelope) -> Result<Value> {
    wire_request(root, value)
}
fn wire_request(root: &Path, value: &impl Serialize) -> Result<Value> {
    let mut s = UnixStream::connect(root.join("run/control.sock")).map_err(|_| {
        anyhow::anyhow!(
            "Daemon is offline. Start kagnode-daemon.service; terminal exit never stops it."
        )
    })?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 16384, "Terminal request exceeded limits");
    bytes.push(b'\n');
    s.write_all(&bytes)?;
    let mut reply = Vec::new();
    s.take(2 * 1024 * 1024).read_to_end(&mut reply)?;
    let d: Value = serde_json::from_slice(&reply)?;
    ensure!(
        d["ok"] == true,
        "{}",
        d["error"].as_str().unwrap_or("Daemon request failed")
    );
    Ok(d["value"].clone())
}
pub async fn serve(store: Store) -> Result<()> {
    let socket = store.root.join("run/control.sock");
    if socket.exists() {
        ensure!(
            socket.symlink_metadata()?.file_type().is_socket(),
            "Unexpected terminal socket path"
        );
        ensure!(
            UnixStream::connect(&socket).is_err(),
            "Terminal API already active"
        );
        std::fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let workers = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(cred) = stream.peer_cred() else {
            continue;
        };
        let uid = cred.uid();
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let state = store.clone();
        let workers = workers.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut input = BufReader::new(stream);
            let mut line = String::new();
            let read = tokio::time::timeout(
                Duration::from_secs(3),
                (&mut input).take(16385).read_line(&mut line),
            )
            .await;
            let result = match read {
                Ok(Ok(_)) if line.len() <= 16384 && line.ends_with('\n') => {
                    match serde_json::from_str::<crate::roles::Envelope>(&line) {
                        Ok(req) => match workers.clone().try_acquire_owned() {
                            Ok(worker) => tokio::task::spawn_blocking(move || {
                                let _worker = worker;
                                authenticated_dispatch(&state, uid, req)
                            })
                            .await
                            .unwrap_or_else(|_| Err(anyhow::anyhow!("Terminal worker failed"))),
                            Err(_) => Err(anyhow::anyhow!("Terminal authentication workers busy")),
                        },
                        Err(_) => Err(anyhow::anyhow!("Invalid terminal request")),
                    }
                }
                _ => Err(anyhow::anyhow!("Terminal request exceeded limits")),
            };
            use zeroize::Zeroize;
            line.zeroize();
            let reply = match result {
                Ok(value) => json!({"ok":true,"value":value}),
                Err(e) => json!({"ok":false,"error":e.to_string()}),
            };
            let mut stream = input.into_inner();
            let encoded = serde_json::to_vec(&reply).unwrap_or_default();
            let encoded = if encoded.len() <= 2 * 1024 * 1024 {
                encoded
            } else {
                br#"{"ok":false,"error":"Response exceeded limits"}"#.to_vec()
            };
            let _ = tokio::time::timeout(Duration::from_secs(3), stream.write_all(&encoded)).await;
            let _ = stream.shutdown().await;
        });
    }
}
pub fn authenticated_dispatch(
    store: &Store,
    uid: u32,
    request: crate::roles::Envelope,
) -> Result<Value> {
    let value = crate::roles::handle(store, uid, &request)?;
    use crate::roles::Action;
    match &request.payload {
        Action::Overview => {
            let h = History::open(&store.root)?;
            let latest = h.latest()?;
            let stale = latest
                .as_ref()
                .is_none_or(|v| !(0..=30).contains(&(auth::now() - v.at)));
            Ok(
                json!({"nodes":[{"id":"local","health":if stale{"unknown"}else{"online"},"last_sample":latest,"history_trim_events":h.health()?}]}),
            )
        }
        Action::Metrics { name, since, until } => Ok(
            json!({"node":"local","metric":name,"points":History::open(&store.root)?.query(name,*since,*until,600)?}),
        ),
        Action::Retention => {
            let (r, p) = policy(store)?;
            Ok(json!({"revision":r,"policy":p,"presets_days":[2,5,7,30,90,180,365]}))
        }
        _ => Ok(value),
    }
}
pub async fn collect(store: Store) {
    let mut collector = Collector::default();
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut count = 0;
    loop {
        tick.tick().await;
        let at = auth::now();
        let sample = collector.sample(Path::new("/proc"), at);
        let state = store.clone();
        count += 1;
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut h = History::open(&state.root)?;
            h.append(&sample)?;
            if count % 6 == 0 {
                h.compact(at, &policy(&state)?.1)?;
            }
            Ok(())
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("Host metrics could not be recorded; previous history retained");
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shortening_requires_confirmation_and_revision() -> Result<()> {
        let t = tempfile::tempdir()?;
        let s = Store::open(&t.path().join("controller"))?;
        s.init(
            "owner@example.test",
            "long-fixture-password",
            crate::store::Profile::Light,
            false,
        )?;
        let req = Request::SetRetention {
            revision: 0,
            policy: Policy {
                days: 2,
                ..Policy::default()
            },
            confirm_trim: false,
        };
        assert!(dispatch(&s, req).is_err());
        dispatch(
            &s,
            Request::SetRetention {
                revision: 0,
                policy: Policy {
                    days: 2,
                    ..Policy::default()
                },
                confirm_trim: true,
            },
        )?;
        assert!(
            dispatch(
                &s,
                Request::SetRetention {
                    revision: 0,
                    policy: Policy::default(),
                    confirm_trim: false
                }
            )
            .is_err()
        );
        Ok(())
    }
}
