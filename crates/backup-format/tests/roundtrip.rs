use kagnode_backup_format::*;
use std::{fs, os::unix::fs::symlink};
fn manifest(id: &str) -> Manifest {
    Manifest {
        format: "kagnode-dbackup/v2".into(),
        site: "site".into(),
        node: "node".into(),
        snapshot: id.into(),
        created_at: 100,
        recipient_generation: "initial".into(),
        catalog: Object {
            sha256: "0".repeat(64),
            bytes: 1,
        },
        objects: vec![],
    }
}
#[test]
fn encrypted_incremental_roundtrip_and_rotation() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let input = temp.path().join("source");
    let objects = temp.path().join("objects");
    fs::create_dir(&input)?;
    fs::create_dir(&objects)?;
    fs::create_dir(input.join("nested"))?;
    let bytes = vec![0x73; CHUNK_BYTES + 1024];
    fs::write(input.join("nested/data"), &bytes)?;
    fs::write(input.join("empty"), [])?;
    let key = age::x25519::Identity::generate();
    let recipient = key.to_public().to_string();
    let mut cache = ChunkIndex::default();
    let first = snapshot(&input, &objects, &recipient, &mut cache, manifest("first"))?;
    let second = snapshot(&input, &objects, &recipient, &mut cache, manifest("second"))?;
    assert_eq!(first.objects, second.objects);
    assert_ne!(
        first.catalog, second.catalog,
        "Catalog uses fresh randomized encryption"
    );
    assert!(
        !read_object(&objects, &first.catalog)?
            .windows(6)
            .any(|s| s == b"nested")
    );
    assert_eq!(
        restore(
            &second,
            &objects,
            &key,
            &temp.path().join("restored"),
            bytes.len() as u64
        )?,
        2
    );
    assert_eq!(fs::read(temp.path().join("restored/nested/data"))?, bytes);
    assert!(
        restore(
            &second,
            &objects,
            &key,
            &temp.path().join("restored"),
            u64::MAX
        )
        .is_err()
    );
    let replacement = age::x25519::Identity::generate();
    let rotated = snapshot(
        &input,
        &objects,
        &replacement.to_public().to_string(),
        &mut cache,
        manifest("rotated"),
    )?;
    assert_ne!(second.objects, rotated.objects);
    assert!(
        restore(
            &rotated,
            &objects,
            &key,
            &temp.path().join("wrong-key"),
            u64::MAX
        )
        .is_err()
    );
    assert!(!temp.path().join("wrong-key").exists());
    Ok(())
}
#[test]
fn corruption_and_size_fail_without_activation() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let input = temp.path().join("source");
    let objects = temp.path().join("objects");
    fs::create_dir(&input)?;
    fs::create_dir(&objects)?;
    fs::write(input.join("data"), b"a private synthetic fixture")?;
    let key = age::x25519::Identity::generate();
    let m = snapshot(
        &input,
        &objects,
        &key.to_public().to_string(),
        &mut ChunkIndex::default(),
        manifest("one"),
    )?;
    let dest = temp.path().join("restore");
    assert!(restore(&m, &objects, &key, &dest, 1).is_err());
    assert!(!dest.exists());
    fs::write(
        objects.join(&m.objects[0].sha256),
        vec![0; m.objects[0].bytes as usize],
    )?;
    assert!(restore(&m, &objects, &key, &dest, 1024).is_err());
    assert!(!dest.exists());
    Ok(())
}
#[test]
fn reject_paths_links_nested_cache_and_bombs() -> anyhow::Result<()> {
    for p in [
        "/etc/passwd",
        "../escape",
        "a/../b",
        "a/./b",
        "a//b",
        "a\\b",
        "a\0b",
    ] {
        assert!(!relative(p), "{p}");
    }
    let temp = tempfile::tempdir()?;
    let input = temp.path().join("source");
    let objects = temp.path().join("objects");
    fs::create_dir(&input)?;
    fs::create_dir(&objects)?;
    fs::create_dir(input.join("cache"))?;
    let key = age::x25519::Identity::generate();
    let recipient = key.to_public().to_string();
    assert!(
        snapshot(
            &input,
            &input.join("cache"),
            &recipient,
            &mut ChunkIndex::default(),
            manifest("one")
        )
        .is_err()
    );
    symlink("/etc/passwd", input.join("link"))?;
    assert!(
        snapshot(
            &input,
            &objects,
            &recipient,
            &mut ChunkIndex::default(),
            manifest("one")
        )
        .is_err()
    );
    let encrypted = encrypt(&vec![0; 4096], &recipient)?;
    assert!(decrypt(&encrypted, &key, 1024).is_err());
    let mut invalid = manifest("one");
    invalid.objects.push(invalid.catalog.clone());
    assert!(invalid.validate().is_err());
    Ok(())
}
