use kagnode_backup_format::{Manifest, Object, digest};
use kagnode_daemon::backup_service::{policy::*, repository::*};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs;
fn policy() -> Policy {
    Policy {
        revision: 1,
        interval_seconds: 3600,
        recovery_point_seconds: 7200,
        keep_snapshots: 3,
        reserve_bytes: 20 * 1024 * 1024 * 1024,
        max_deferral_seconds: 86400,
        bandwidth_percent: 25,
        monthly_node_bytes: None,
        monthly_server_bytes: None,
        required_copies: 1,
    }
}
fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap()
}
fn enroll(r: &mut Repository) -> anyhow::Result<()> {
    let k = key();
    let ticket = r.approve_node("node", &hex::encode(k.public_key().as_ref()), 100)?;
    let message = format!("kagnode-backup-enroll/v1\nsite\nserver\nnode\n{ticket}");
    let proof = hex::encode(k.sign(message.as_bytes()).as_ref());
    r.enroll("node", &ticket, &proof, 100)?;
    assert!(r.enroll("node", &ticket, &proof, 100).is_err());
    Ok(())
}
fn signed(id: &str, at: i64) -> SignedSnapshot {
    let data = b"fixture ciphertext";
    let manifest = Manifest {
        format: "kagnode-dbackup/v2".into(),
        site: "site".into(),
        node: "node".into(),
        snapshot: id.into(),
        created_at: at,
        recipient_generation: "initial".into(),
        catalog: Object {
            sha256: digest(data),
            bytes: data.len() as u64,
        },
        objects: vec![],
    };
    let signature = hex::encode(key().sign(&manifest.bytes().unwrap()).as_ref());
    SignedSnapshot {
        manifest,
        signature,
    }
}
fn commit(r: &mut Repository, id: &str, at: i64) -> anyhow::Result<()> {
    let s = signed(id, at);
    let lease = r.begin(&s, at)?;
    for o in lease.missing {
        r.upload("node", &lease.id, &o.sha256, 0, b"fixture ciphertext", at)?;
    }
    let result = r.finish("node", &lease.id, at)?;
    assert_eq!(result["ciphertext_verified"], true);
    assert_eq!(result["restore_tested"], false);
    assert_eq!(r.finish("node", &lease.id, at + 1000)?, result);
    Ok(())
}
#[test]
fn enrollment_replay_revocation_and_single_owner() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("store");
    let mut r = Repository::create(&root, "site", "server", &policy())?;
    assert!(Repository::open(&root).is_err());
    enroll(&mut r)?;
    let body = b"payload";
    let msg = format!(
        "kagnode-backup-request/v1\nsite\nserver\nnode\nnonce\n101\nbegin\n{}",
        digest(body)
    );
    let signature = hex::encode(key().sign(msg.as_bytes()).as_ref());
    assert!(
        r.authenticate(
            &SignedRequest {
                node: "node",
                nonce: "nonce",
                at: 101,
                operation: "begin",
                body: b"tampered",
                signature: &signature
            },
            101
        )
        .is_err()
    );
    r.authenticate(
        &SignedRequest {
            node: "node",
            nonce: "nonce",
            at: 101,
            operation: "begin",
            body,
            signature: &signature,
        },
        101,
    )?;
    assert!(
        r.authenticate(
            &SignedRequest {
                node: "node",
                nonce: "nonce",
                at: 101,
                operation: "begin",
                body,
                signature: &signature
            },
            101
        )
        .is_err()
    );
    r.revoke("node")?;
    assert!(r.begin(&signed("first", 102), 102).is_err());
    drop(r);
    Repository::open(&root)?;
    Ok(())
}
#[test]
fn interrupted_upload_resumes_and_corruption_retries() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("store");
    let mut r = Repository::create(&root, "site", "server", &policy())?;
    enroll(&mut r)?;
    let s = signed("one", 100);
    let lease = r.begin(&s, 100)?;
    let hash = &s.manifest.catalog.sha256;
    assert!(r.finish("node", &lease.id, 100).is_err());
    r.upload("node", &lease.id, hash, 0, b"fixture", 100)?;
    assert!(
        r.upload("node", &lease.id, hash, 0, b"fixture", 100)
            .is_err()
    );
    drop(r);
    let mut r = Repository::open(&root)?;
    assert_eq!(r.offset("node", &lease.id, hash, 101)?, 7);
    assert!(r.offset("node", &lease.id, hash, 2000).is_err());
    r.renew("node", &lease.id, 2000)?;
    assert!(
        r.upload("node", &lease.id, hash, 7, b" corrupted!", 2000)
            .is_err()
    );
    assert_eq!(r.offset("node", &lease.id, hash, 2000)?, 0);
    r.upload("node", &lease.id, hash, 0, b"fixture ciphertext", 2000)?;
    r.finish("node", &lease.id, 2000)?;
    assert_eq!(r.snapshots("node")?.len(), 1);
    assert!(r.begin(&signed("one", 101), 2000).is_err());
    Ok(())
}
#[test]
fn retention_keeps_latest_verified_rollback_and_pins() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut r = Repository::create(&tmp.path().join("store"), "site", "server", &policy())?;
    enroll(&mut r)?;
    commit(&mut r, "one", 100)?;
    commit(&mut r, "two", 101)?;
    assert!(r.delete("node", "one", "admin").is_err());
    assert!(r.mark_restore_tested("node", "one", "node").is_err());
    r.mark_restore_tested("node", "one", "restore-runner")?;
    commit(&mut r, "three", 102)?;
    assert!(r.delete("node", "three", "admin").is_err());
    assert!(r.delete("node", "one", "admin").is_err());
    r.pin("node", "two", true)?;
    assert!(r.delete("node", "two", "admin").is_err());
    r.pin("node", "two", false)?;
    assert!(r.delete("node", "two", "node").is_err());
    let restore_lease =
        r.begin_restore("node", "two", "restore-runner", kagnode_daemon::auth::now())?;
    assert!(r.delete("node", "two", "admin").is_err());
    r.end_restore(&restore_lease, "restore-runner")?;
    assert!(r.delete("node", "two", "admin").is_err());
    for (id, at) in [("four", 103), ("five", 104), ("six", 105)] {
        commit(&mut r, id, at)?;
        r.mark_restore_tested("node", id, "restore-runner")?;
    }
    r.delete("node", "two", "admin")?;
    assert!(r.begin(&signed("two", 101), 102).is_err());
    assert_eq!(
        r.gc(100000)?,
        0,
        "shared object still needed by protected snapshots"
    );
    assert_eq!(r.snapshots("node")?.len(), 5);
    Ok(())
}
#[test]
fn transfer_caps_space_reserve_and_storage_identity() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("store");
    let mut p = policy();
    p.monthly_node_bytes = Some(1);
    let mut r = Repository::create(&root, "site", "server", &p)?;
    enroll(&mut r)?;
    let s = signed("one", 100);
    let lease = r.begin(&s, 100)?;
    assert!(
        r.upload(
            "node",
            &lease.id,
            &s.manifest.catalog.sha256,
            0,
            b"fixture ciphertext",
            100
        )
        .is_err()
    );
    assert_eq!(
        r.offset("node", &lease.id, &s.manifest.catalog.sha256, 100)?,
        0
    );
    p.revision += 1;
    p.reserve_bytes = u64::MAX;
    r.save_policy(&p, "admin")?;
    assert!(r.begin(&signed("two", 101), 101).is_err());
    assert!(!r.eligibility(ArrayHealth::Degraded, 100, 101));
    assert!(r.eligibility(ArrayHealth::Healthy, 100, 101));
    assert!(!r.eligibility(ArrayHealth::Healthy, 100, 1000));
    drop(r);
    let moved = tmp.path().join("moved");
    fs::rename(&root, &moved)?;
    fs::create_dir(&root)?;
    fs::copy(moved.join("repository.json"), root.join("repository.json"))?;
    assert!(Repository::open(&root).is_err());
    Ok(())
}
#[test]
fn unsafe_never_overridden_and_busy_has_hysteresis() {
    let p = policy();
    assert_eq!(
        admission(Readiness::Unsafe, 100, 100, 999999, true, &p),
        Admission::Blocked
    );
    assert_eq!(
        admission(Readiness::Ready, 0, 100, 0, false, &p),
        Admission::Blocked
    );
    assert_eq!(
        admission(Readiness::Busy, 100, 100, 0, false, &p),
        Admission::Wait
    );
    assert_eq!(
        admission(Readiness::Busy, 100, 100, 86400, false, &p),
        Admission::Throttled
    );
    let mut h = Hysteresis::default();
    for t in [0, 60, 120] {
        assert_eq!(h.observe(t, true, false), Readiness::Ready);
    }
    assert_eq!(h.observe(180, true, false), Readiness::Busy);
    for t in [240, 300, 360] {
        assert_eq!(h.observe(t, false, true), Readiness::Busy);
    }
    assert_eq!(h.observe(420, false, true), Readiness::Ready);
}
