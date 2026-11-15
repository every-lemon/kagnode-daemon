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

#[test]
fn f2_failed_uploads_do_not_charge_other_nodes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = Repository::create(
        &tmp.path().join("s"),
        "site",
        "server",
        &policy(Some(4 * 1024 * 1024)),
    )
    .unwrap();
    enroll(&mut r, "evil", 1);
    enroll(&mut r, "victim", 2);
    let good = blob("good", 1, 1024 * 1024);
    let bad = blob("bad", 2, 1024 * 1024);
    let a = r
        .begin(&signed("evil", 1, "s1", 100, b"cat", &[good.clone()]), 100)
        .unwrap();
    for _ in 0..4 {
        assert!(
            r.upload("evil", &a.id, &digest(&good), 0, &bad, 100)
                .is_err()
        );
    }
    let b = r
        .begin(
            &signed("victim", 2, "s1", 100, b"cat", &[good.clone()]),
            100,
        )
        .unwrap();
    assert!(
        r.upload("victim", &b.id, &digest(&good), 0, &good, 100)
            .is_ok()
    );
}
#[test]
fn f3_abandoned_partials_are_collected_and_quota_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("s");
    let mut r = Repository::create(&root, "site", "server", &policy(None)).unwrap();
    enroll(&mut r, "n", 1);
    let data = blob("data", 1, 1024 * 1024);
    let a = r
        .begin(&signed("n", 1, "s1", 100, b"cat", &[data.clone()]), 100)
        .unwrap();
    r.upload("n", &a.id, &digest(&data), 0, &data[..100], 100)
        .unwrap();
    r.gc(2000).unwrap();
    assert_eq!(fs::read_dir(root.join("partial/n")).unwrap().count(), 0);
    // Sparse synthetic partial charges the full durable size without writing 64 MiB.
    let b = r
        .begin(&signed("n", 1, "s2", 2000, b"cat", &[data.clone()]), 2000)
        .unwrap();
    let partial = root
        .join("partial/n")
        .join(format!("{}-{}", b.id, digest(&data)));
    fs::File::create(&partial)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    assert!(
        r.upload("n", &b.id, &digest(b"cat"), 0, b"cat", 2000)
            .is_err()
    );
}

#[test]
fn f4_control_operations_do_not_open_verified_object_payloads() {
    use std::os::fd::{AsRawFd, FromRawFd};
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("s");
    let mut r = Repository::create(&root, "site", "server", &policy(None)).unwrap();
    enroll(&mut r, "n", 1);
    let data = blob("original", 1, 1024 * 1024);
    commit(&mut r, "n", 1, "s1", 100, b"cat", &[data.clone()]);
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(fd >= 0);
    let fd = unsafe { std::fs::File::from_raw_fd(fd) };
    let path = std::ffi::CString::new(root.join("objects/n").join(digest(&data)).to_str().unwrap())
        .unwrap();
    assert!(unsafe { libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), libc::IN_OPEN) } >= 0);
    let a = r
        .begin(&signed("n", 1, "s2", 101, b"catalog", &[data]), 101)
        .unwrap();
    r.upload("n", &a.id, &digest(b"catalog"), 0, b"cat", 101)
        .unwrap();
    r.renew("n", &a.id, 102).unwrap();
    r.upload("n", &a.id, &digest(b"catalog"), 3, b"alog", 102)
        .unwrap();
    r.finish("n", &a.id, 102).unwrap();
    let mut events = [0u8; 4096];
    assert_eq!(
        unsafe { libc::read(fd.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) },
        -1,
        "control operations opened stored ciphertext"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN)
    );
}

#[test]
fn f5_unverified_arrivals_cannot_displace_recovery_points() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = Repository::create(&tmp.path().join("s"), "site", "server", &policy(None)).unwrap();
    enroll(&mut r, "n", 1);
    for (id, t) in [
        ("good1", 100),
        ("good2", 101),
        ("junk1", 102),
        ("junk2", 103),
    ] {
        commit(&mut r, "n", 1, id, t, id.as_bytes(), &[]);
    }
    assert!(r.delete("n", "good1", "admin").is_err());
    assert!(r.delete("n", "good2", "admin").is_err());
    // This newly received snapshot claims an old creation date. Receipt order wins.
    let a = r
        .begin(&signed("n", 1, "backdated", 1, b"cat", &[]), 104)
        .unwrap();
    for o in a.missing {
        r.upload("n", &a.id, &o.sha256, 0, b"cat", 104).unwrap();
    }
    r.finish("n", &a.id, 104).unwrap();
    assert_eq!(r.snapshots("n").unwrap()[0]["id"], "backdated");
}
