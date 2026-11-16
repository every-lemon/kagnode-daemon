//! V1 compatibility and V2 encrypted objects. No recovery identities belong on a backup server.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
};
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OBJECT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 65536;
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn relative(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 4096
        && !s.contains('\\')
        && !s.contains('\0')
        && s.split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && Path::new(s)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub sha256: String,
    pub bytes: u64,
}
impl Object {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            hash(&self.sha256) && (1..=MAX_OBJECT_BYTES as u64).contains(&self.bytes),
            "Invalid encrypted object"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub site: String,
    pub node: String,
    pub snapshot: String,
    pub created_at: i64,
    pub recipient_generation: String,
    pub catalog: Object,
    pub objects: Vec<Object>,
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "kagnode-dbackup/v2",
            "Unsupported backup format"
        );
        ensure!(
            [
                &self.site,
                &self.node,
                &self.snapshot,
                &self.recipient_generation
            ]
            .into_iter()
            .all(|s| identifier(s))
                && self.created_at >= 0,
            "Invalid backup identity"
        );
        ensure!(
            self.objects.len() <= MAX_ENTRIES,
            "Object list exceeds limit"
        );
        self.catalog.validate()?;
        let mut seen = std::collections::HashSet::new();
        seen.insert(&self.catalog.sha256);
        for o in &self.objects {
            o.validate()?;
            ensure!(seen.insert(&o.sha256), "Duplicate object identity");
        }
        Ok(())
    }
    pub fn all_objects(&self) -> impl Iterator<Item = &Object> {
        std::iter::once(&self.catalog).chain(self.objects.iter())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let raw = serde_json::to_vec(self)?;
        ensure!(raw.len() <= MAX_MANIFEST_BYTES, "Manifest too large");
        Ok(raw)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub mode: u32,
    pub chunks: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u32,
    pub files: Vec<FileEntry>,
}
impl Catalog {
    pub fn validate(&self, m: &Manifest) -> Result<()> {
        ensure!(
            self.schema == 2 && self.files.len() <= MAX_ENTRIES,
            "Invalid file catalog"
        );
        let objects: std::collections::HashSet<_> =
            m.objects.iter().map(|o| o.sha256.as_str()).collect();
        let mut paths = std::collections::HashSet::new();
        for f in &self.files {
            ensure!(
                relative(&f.path)
                    && paths.insert(&f.path)
                    && hash(&f.sha256)
                    && f.mode & !0o777 == 0
                    && f.chunks.len() <= MAX_ENTRIES,
                "Invalid file entry"
            );
            ensure!(
                f.chunks.iter().all(|id| objects.contains(id.as_str())),
                "File references missing object"
            );
            ensure!(
                f.bytes <= CHUNK_BYTES as u64 * f.chunks.len() as u64,
                "File length exceeds chunks"
            );
        }
        Ok(())
    }
}
pub fn encrypt(data: &[u8], recipient: &str) -> Result<Vec<u8>> {
    ensure!(
        data.len() <= MAX_MANIFEST_BYTES,
        "Plaintext object exceeds bound"
    );
    let key: age::x25519::Recipient = recipient
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid age recipient"))?;
    let compressed = zstd::stream::encode_all(data, 3)?;
    let mut output = Vec::new();
    let mut writer = age::Encryptor::with_recipients(std::iter::once(&key as &dyn age::Recipient))?
        .wrap_output(&mut output)?;
    writer.write_all(&compressed)?;
    writer.finish()?;
    ensure!(
        output.len() <= MAX_OBJECT_BYTES,
        "Encrypted object exceeds bound"
    );
    Ok(output)
}
pub fn decrypt(data: &[u8], identity: &age::x25519::Identity, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        data.len() <= MAX_OBJECT_BYTES && limit <= MAX_MANIFEST_BYTES,
        "Encrypted object exceeds bound"
    );
    let reader =
        age::Decryptor::new(data)?.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let decoder = zstd::stream::read::Decoder::new(reader)?;
    let mut clear = Vec::new();
    decoder.take(limit as u64 + 1).read_to_end(&mut clear)?;
    ensure!(clear.len() <= limit, "Decompressed object exceeds bound");
    Ok(clear)
}
/// Cache is node-local; it contains only fingerprints and ciphertext references, never decryption keys.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkIndex {
    pub recipient: String,
    pub chunks: BTreeMap<String, Object>,
}
pub fn put_object(root: &Path, data: &[u8]) -> Result<Object> {
    ensure!(
        !data.is_empty() && data.len() <= MAX_OBJECT_BYTES,
        "Invalid object length"
    );
    let id = digest(data);
    let p = root.join(&id);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
    {
        Ok(mut f) => {
            if let Err(error) = f.write_all(data).and_then(|()| f.sync_all()) {
                drop(f);
                let _ = fs::remove_file(&p);
                return Err(error.into());
            }
            fs::File::open(root)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                read_object(
                    root,
                    &Object {
                        sha256: id.clone(),
                        bytes: data.len() as u64
                    }
                )? == data,
                "Existing ciphertext object changed"
            );
        }
        Err(e) => return Err(e.into()),
    }
    Ok(Object {
        sha256: id,
        bytes: data.len() as u64,
    })
}
pub fn read_object(root: &Path, o: &Object) -> Result<Vec<u8>> {
    o.validate()?;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(&o.sha256))?;
    ensure!(
        f.metadata()?.is_file() && f.metadata()?.len() == o.bytes,
        "Object length changed"
    );
    let mut data = Vec::new();
    f.take(o.bytes + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 == o.bytes,
        "Object size changed while reading"
    );
    ensure!(digest(&data) == o.sha256, "Ciphertext checksum failed");
    Ok(data)
}
/// Input must be an adapter-created consistent snapshot, not a live application directory.
pub fn snapshot(
    input: &Path,
    objects: &Path,
    recipient: &str,
    index: &mut ChunkIndex,
    mut manifest: Manifest,
) -> Result<Manifest> {
    ensure!(
        input.is_dir() && !input.is_symlink() && objects.is_dir() && !objects.is_symlink(),
        "Use regular input and object directories"
    );
    let source = input.canonicalize()?;
    let cache = objects.canonicalize()?;
    ensure!(
        !source.starts_with(&cache) && !cache.starts_with(&source),
        "Use disjoint snapshot input and object directories"
    );
    if index.recipient != recipient {
        index.chunks.clear();
        index.recipient = recipient.into();
    }
    fn walk(root: &Path, path: &Path, out: &mut Vec<String>) -> Result<()> {
        ensure!(
            path.strip_prefix(root)?.components().count() <= 64,
            "Snapshot directory depth exceeds limit"
        );
        for entry in fs::read_dir(path)? {
            let e = entry?;
            let kind = e.file_type()?;
            ensure!(!kind.is_symlink(), "Snapshot contains a symlink");
            if kind.is_dir() {
                walk(root, &e.path(), out)?;
            } else {
                ensure!(kind.is_file(), "Snapshot contains a special file");
                out.push(
                    e.path()
                        .strip_prefix(root)?
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("Non-UTF8 path"))?
                        .to_owned(),
                );
                ensure!(out.len() <= MAX_ENTRIES, "Snapshot has too many files");
            }
        }
        Ok(())
    }
    let mut names = Vec::new();
    walk(input, input, &mut names)?;
    names.sort();
    let mut files = Vec::new();
    let mut unique = BTreeMap::new();
    for name in names {
        ensure!(relative(&name), "Unsafe snapshot path");
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(input.join(&name))?;
        let before = f.metadata()?;
        let mut total = 0;
        let mut file_hash = Sha256::new();
        let mut chunks = Vec::new();
        loop {
            let mut clear = vec![0; CHUNK_BYTES];
            let mut n = 0;
            while n < clear.len() {
                let got = f.read(&mut clear[n..])?;
                if got == 0 {
                    break;
                }
                n += got;
            }
            if n == 0 {
                break;
            }
            clear.truncate(n);
            file_hash.update(&clear);
            total += n as u64;
            let fingerprint = digest(&clear);
            let cached = index
                .chunks
                .get(&fingerprint)
                .filter(|o| read_object(objects, o).is_ok())
                .cloned();
            let object = match cached {
                Some(o) => o,
                None => put_object(objects, &encrypt(&clear, recipient)?)?,
            };
            index.chunks.insert(fingerprint, object.clone());
            chunks.push(object.sha256.clone());
            ensure!(chunks.len() <= MAX_ENTRIES, "File chunk limit exceeded");
            unique.insert(object.sha256.clone(), object);
            ensure!(
                unique.len() <= MAX_ENTRIES,
                "Snapshot object limit exceeded"
            );
        }
        let after = f.metadata()?;
        ensure!(
            total == before.len()
                && before.len() == after.len()
                && before.modified()? == after.modified()?,
            "Snapshot input changed while reading"
        );
        files.push(FileEntry {
            path: name,
            bytes: total,
            sha256: hex::encode(file_hash.finalize()),
            mode: before.permissions().mode() & 0o777,
            chunks,
        });
    }
    index.chunks.retain(|_, o| unique.contains_key(&o.sha256));
    let catalog = Catalog { schema: 2, files };
    let bytes = serde_json::to_vec(&catalog)?;
    manifest.objects = unique.into_values().collect();
    manifest.catalog = put_object(objects, &encrypt(&bytes, recipient)?)?;
    manifest.validate()?;
    catalog.validate(&manifest)?;
    Ok(manifest)
}
/// Always recover to a new directory. A failed recovery is removed, never activated.
pub fn restore(
    m: &Manifest,
    objects: &Path,
    identity: &age::x25519::Identity,
    destination: &Path,
    max_bytes: u64,
) -> Result<usize> {
    m.validate()?;
    ensure!(
        !destination.exists() && !destination.is_symlink(),
        "Restore destination already exists"
    );
    let catalog: Catalog = serde_json::from_slice(&decrypt(
        &read_object(objects, &m.catalog)?,
        identity,
        MAX_MANIFEST_BYTES,
    )?)?;
    catalog.validate(m)?;
    let total = catalog.files.iter().try_fold(0u64, |n, f| {
        n.checked_add(f.bytes)
            .ok_or_else(|| anyhow::anyhow!("Restore size overflow"))
    })?;
    ensure!(total <= max_bytes, "Restore exceeds approved size");
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<usize> {
        let lookup: BTreeMap<_, _> = m.objects.iter().map(|o| (&o.sha256, o)).collect();
        for entry in &catalog.files {
            let p = destination.join(&entry.path);
            fs::create_dir_all(p.parent().unwrap())?;
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&p)?;
            let mut h = Sha256::new();
            let mut written = 0u64;
            for id in &entry.chunks {
                let clear = decrypt(&read_object(objects, lookup[id])?, identity, CHUNK_BYTES)?;
                written += clear.len() as u64;
                ensure!(
                    written <= entry.bytes,
                    "Restored file exceeds declared size"
                );
                out.write_all(&clear)?;
                h.update(&clear);
            }
            ensure!(
                written == entry.bytes && hex::encode(h.finalize()) == entry.sha256,
                "Restored file integrity failed"
            );
            out.sync_all()?;
            fs::set_permissions(&p, fs::Permissions::from_mode(entry.mode & 0o700))?;
        }
        Ok(catalog.files.len())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyPart {
    pub sequence: u32,
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Deserialize)]
pub struct LegacyManifest {
    pub format: String,
    pub encryption: String,
    pub parts: Vec<LegacyPart>,
    #[serde(rename = "encryptedSha256")]
    pub encrypted_sha256: String,
}
impl LegacyManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "kagnode-dbackup/v1"
                && self.encryption == "age"
                && hash(&self.encrypted_sha256)
                && (1..=998).contains(&self.parts.len()),
            "Invalid legacy manifest"
        );
        for (i, p) in self.parts.iter().enumerate() {
            ensure!(
                p.sequence == i as u32 + 1
                    && p.name == format!("payload.tar.zst.age.part{:04}", i + 1)
                    && p.bytes > 0
                    && p.bytes < 2_000_000_000
                    && hash(&p.sha256),
                "Invalid legacy part"
            );
        }
        Ok(())
    }
}
