// Independent review reproductions for Daemon PR #28 (commit 9879cac).
// Synthetic data only: ephemeral keys, temporary directories, fake "ciphertext".
// This file lives in a scratch copy, not in the reviewed branch.
use kagnode_backup_format::{Manifest, Object, digest};
use kagnode_daemon::backup_service::{policy::*, repository::*};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs;

fn policy(server_cap: Option<u64>) -> Policy {
    Policy {
        revision: 1,
        interval_seconds: 3600,
        recovery_point_seconds: 7200,
        keep_snapshots: 3,
        reserve_bytes: 1,
        max_deferral_seconds: 86400,
        bandwidth_percent: 25,
        monthly_node_bytes: None,
        monthly_server_bytes: server_cap,
        required_copies: 1,
    }
}
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn enroll(r: &mut Repository, node: &str, seed: u8) {
    let k = key(seed);
    let ticket = r
        .approve_node(node, &hex::encode(k.public_key().as_ref()), 100)
        .unwrap();
    let message = format!("kagnode-backup-enroll/v1\nsite\nserver\n{node}\n{ticket}");
    let proof = hex::encode(k.sign(message.as_bytes()).as_ref());
    r.enroll(node, &ticket, &proof, 100).unwrap();
}
fn blob(tag: &str, n: usize, len: usize) -> Vec<u8> {
    let mut v = vec![(n % 251) as u8; len];
    let t = format!("{tag}-{n}");
    v[..t.len().min(len)].copy_from_slice(&t.as_bytes()[..t.len().min(len)]);
    v
}
fn object(data: &[u8]) -> Object {
    Object {
        sha256: digest(data),
        bytes: data.len() as u64,
    }
}
fn signed(
    node: &str,
    seed: u8,
    id: &str,
    at: i64,
    catalog: &[u8],
    objects: &[Vec<u8>],
) -> SignedSnapshot {
    let manifest = Manifest {
        format: "kagnode-dbackup/v2".into(),
        site: "site".into(),
        node: node.into(),
        snapshot: id.into(),
        created_at: at,
        recipient_generation: "initial".into(),
        catalog: object(catalog),
        objects: objects.iter().map(|o| object(o)).collect(),
    };
    let signature = hex::encode(key(seed).sign(&manifest.bytes().unwrap()).as_ref());
    SignedSnapshot {
        manifest,
        signature,
    }
}
/// Upload every missing object (1 MiB chunks) and finish.
fn commit(
    r: &mut Repository,
    node: &str,
    seed: u8,
    id: &str,
    at: i64,
    cat: &[u8],
    objs: &[Vec<u8>],
) {
    let s = signed(node, seed, id, at, cat, objs);
    let lease = r.begin(&s, at).unwrap();
    for o in &lease.missing {
        let data = std::iter::once(cat.to_vec())
            .chain(objs.iter().cloned())
            .find(|d| digest(d) == o.sha256)
            .unwrap();
        let mut off = 0;
        while off < data.len() {
            let end = (off + 1024 * 1024).min(data.len());
            r.upload(node, &lease.id, &o.sha256, off as u64, &data[off..end], at)
                .unwrap();
            off = end;
        }
    }
    r.finish(node, &lease.id, at).unwrap();
}

#[test]
fn f1_node_slots_and_progress_limited_renewal() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = Repository::create(&tmp.path().join("s"), "site", "server", &policy(None)).unwrap();
    enroll(&mut r, "evil", 1);
    enroll(&mut r, "victim", 2);
    let a = r
        .begin(&signed("evil", 1, "s1", 100, b"catalog", &[]), 100)
        .unwrap();
    assert!(
        r.begin(&signed("evil", 1, "s2", 100, b"cat2", &[]), 100)
            .is_err()
    );
    assert!(
        r.begin(&signed("victim", 2, "v1", 100, b"cat3", &[]), 100)
            .is_ok()
    );
    assert!(r.renew("evil", &a.id, 800).is_err());
    r.upload("evil", &a.id, &digest(b"catalog"), 0, b"cat", 800)
        .unwrap();
    assert!(r.renew("evil", &a.id, 800).is_ok());
    assert!(r.renew("evil", &a.id, 801).is_err());
    assert!(r.renew("evil", &a.id, 86500).is_err());
}
