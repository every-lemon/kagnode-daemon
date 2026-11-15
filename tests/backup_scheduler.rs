use anyhow::Result;
use kagnode_backup_format::{Manifest, Object, digest};
use kagnode_daemon::backup_service::{
    agent::Target,
    policy::{Admission, Policy},
    scheduler::{Queue, Schedule},
};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
fn config(root: &Path) -> Schedule {
    let target = Target {
        site: "site".into(),
        server: "one".into(),
        endpoint: "https://127.0.0.1:9443".into(),
        ca: root.join("ca"),
        identity_pem: root.join("identity"),
    };
    let mut other = target.clone();
    other.server = "two".into();
    Schedule {
        id: "daily".into(),
        node: "node".into(),
        signing_key: root.join("key"),
        manifest: root.join("manifest"),
        objects: root.join("objects"),
        readiness: root.join("readiness"),
        targets: vec![target, other],
        policy: Policy {
            revision: 1,
            interval_seconds: 60,
            recovery_point_seconds: 120,
            keep_snapshots: 2,
            reserve_bytes: 0,
            max_deferral_seconds: 60,
            bandwidth_percent: 25,
            monthly_node_bytes: None,
            monthly_server_bytes: None,
            required_copies: 1,
        },
        next_run: 100,
        paused: false,
        link_bytes_per_second: 4096,
    }
}
fn manifest() -> Manifest {
    Manifest {
        format: "kagnode-dbackup/v2".into(),
        site: "site".into(),
        node: "node".into(),
        snapshot: "sample".into(),
        created_at: 100,
        recipient_generation: "initial".into(),
        catalog: Object {
            sha256: digest(b"ciphertext"),
            bytes: 10,
        },
        objects: vec![],
    }
}
#[test]
fn schedule_survives_restart_without_duplicate_or_missed_copies() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("queue");
    let c = config(tmp.path());
    let m = manifest();
    let mut q = Queue::open(&root)?;
    assert!(Queue::open(&root).is_err());
    assert!(!q.enqueue_due(&c, &m, 99)?);
    assert!(q.enqueue_due(&c, &m, 100)?);
    let first = q.next(100)?.unwrap();
    q.start(first.id)?;
    q.finish(&first,Some(&json!({"snapshot":"sample","server":"one","ciphertext_verified":true,"verified_at":100})),100)?;
    let second = q.next(100)?.unwrap();
    assert_eq!(second.target.server, "two");
    q.start(second.id)?;
    drop(q); // Simulated restart after durable start, before a receipt.
    let mut q = Queue::open(&root)?;
    let retry = q.next(101)?.unwrap();
    assert_eq!(retry.id, second.id);
    assert!(!q.enqueue_due(&c, &m, 1000)?);
    assert_eq!(q.status()?["transfers"].as_array().unwrap().len(), 2);
    q.start(retry.id)?;
    q.finish(&retry, None, 101)?;
    assert!(q.next(102)?.is_none());
    let retry = q.next(1000)?.unwrap();
    q.start(retry.id)?;
    assert!(q.finish(&retry,Some(&json!({"snapshot":"sample","server":"other","ciphertext_verified":true,"verified_at":100})),1000).is_err());
    q.finish(&retry,Some(&json!({"snapshot":"sample","server":"two","ciphertext_verified":true,"verified_at":100})),1000)?;
    assert!(q.next(2000)?.is_none());
    Ok(())
}
#[test]
fn schedule_freezes_input_and_bounds_retries() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut c = config(tmp.path());
    let m = manifest();
    let mut q = Queue::open(&tmp.path().join("q"))?;
    c.paused = true;
    assert!(!q.enqueue_due(&c, &m, 100)?);
    c.paused = false;
    assert!(q.enqueue_due(&c, &m, 100)?);
    let mut changed = m.clone();
    changed.created_at = 101;
    assert!(q.enqueue_due(&c, &changed, 200).is_err());
    c.targets.clear();
    assert!(c.validate().is_err());
    for attempt in 0..20 {
        let w = q.next(100 + attempt * 4000)?.unwrap();
        assert_eq!(w.schedule.targets.len(), 2);
        q.start(w.id)?;
        q.finish(&w, None, 100 + attempt * 4000)?;
    }
    assert!(q.next(100000)?.is_none());
    assert!(
        q.status()?["transfers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["state"] == "blocked")
    );
    Ok(())
}
#[test]
fn readiness_staleness_unsafe_and_busy_are_enforced() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let c = config(tmp.path());
    let write = |state: &str, at: i64| -> Result<()> {
        fs::write(
            &c.readiness,
            serde_json::to_vec(&json!({"state":state,"observed_at":at}))?,
        )?;
        fs::set_permissions(&c.readiness, fs::Permissions::from_mode(0o600))?;
        Ok(())
    };
    write("ready", 100)?;
    assert_eq!(c.gate(100, 0)?, Admission::Normal);
    assert_eq!(c.gate(191, 0)?, Admission::Blocked);
    write("unsafe", 200)?;
    assert_eq!(c.gate(200, 0)?, Admission::Blocked);
    write("busy", 200)?;
    assert_eq!(c.gate(200, 190)?, Admission::Wait);
    assert_eq!(c.gate(200, 0)?, Admission::Throttled);
    write("ready", 300)?;
    assert_eq!(c.gate(200, 0)?, Admission::Blocked);
    Ok(())
}
