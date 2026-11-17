//! Maintainer-only, explicitly unqualified Rust candidate packaging.
//! This module never installs, publishes, activates or migrates a runtime.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const PUBLIC_KEY: &[u8] = include_bytes!("../packaging/release-public.pem");
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const RESERVE: u64 = 20 * 1024 * 1024 * 1024;
const BUILD_BUDGET: u64 = 8 * 1024 * 1024 * 1024;
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const BINARIES: &[&str] = &["kagnode", "kagnode-backup-server"];

#[derive(Clone)]
pub struct BuildOptions {
    pub source: PathBuf,
    pub work: PathBuf,
    pub output: PathBuf,
    pub target: String,
    pub signing_fd: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub sha256: String,
    pub size: u64,
    pub kind: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub repository: String,
    pub version: String,
    pub product_version: String,
    pub source_commit: String,
    pub source_tree: String,
    pub epoch: u64,
    pub runtime: String,
    pub target: String,
    pub channel: String,
    pub native_qualification: String,
    pub production_eligible: bool,
    pub rustc: String,
    pub binaries: BTreeMap<String, Asset>,
    pub assets: BTreeMap<String, Asset>,
    pub source_inventory_sha256: String,
}
#[derive(Clone, Debug)]
struct Input {
    path: String,
    sha256: String,
    size: u64,
    mode: u32,
}
#[derive(Debug)]
struct Snapshot {
    head: String,
    tree: String,
    epoch: u64,
    version: String,
    files: Vec<Input>,
    inventory_sha256: String,
}
#[derive(Clone)]
struct Resources {
    root: PathBuf,
    initial_free: u64,
}
impl Resources {
    fn new(root: &Path) -> Result<Self> {
        let free = free_bytes(root)?;
        ensure!(
            free >= RESERVE + BUILD_BUDGET,
            "Reserve plus estimated candidate build space unavailable"
        );
        let r = Self {
            root: root.into(),
            initial_free: free,
        };
        r.check()?;
        Ok(r)
    }
    fn check(&self) -> Result<()> {
        let free = free_bytes(&self.root)?;
        ensure!(
            free >= RESERVE + 256 * 1024 * 1024,
            "Disk reserve guard stopped candidate build"
        );
        ensure!(
            self.initial_free.saturating_sub(free) <= BUILD_BUDGET,
            "Candidate build exceeded its space budget"
        );
        let mem = std::fs::read_to_string("/proc/meminfo")?;
        let available = mem
            .lines()
            .find_map(|l| {
                l.strip_prefix("MemAvailable:")
                    .and_then(|s| s.split_whitespace().next())
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(0);
        ensure!(
            available >= 2 * 1024 * 1024,
            "Memory headroom guard stopped candidate build"
        );
        Ok(())
    }
}
fn free_bytes(path: &Path) -> Result<u64> {
    let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut out = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), out.as_mut_ptr()) } == 0,
        "Cannot inspect candidate filesystem capacity"
    );
    let s = unsafe { out.assume_init() };
    Ok(s.f_bavail.saturating_mul(s.f_frsize))
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn file_hash(path: &Path) -> Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() <= MAX_TOTAL,
        "Candidate hash input must be a bounded independent regular file"
    );
    let mut h = Sha256::new();
    let mut block = [0u8; 65536];
    loop {
        let n = f.read(&mut block)?;
        if n == 0 {
            break;
        }
        h.update(&block[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn fixed_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir)),
        "Use absolute candidate paths without traversal"
    );
    for p in path.ancestors().filter(|p| p.exists()) {
        let m = p.symlink_metadata()?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "Candidate directory path must not contain symlinks"
        );
        ensure!(
            m.mode() & 0o022 == 0 || (p == Path::new("/tmp") && m.mode() & 0o1000 != 0),
            "Candidate directories must not be shared writable"
        );
        ensure!(
            m.uid() == 0 || m.uid() == unsafe { libc::geteuid() },
            "Candidate directory ancestry must be publisher-owned or root-owned"
        );
    }
    Ok(())
}
fn private_new_directory(path: &Path) -> Result<()> {
    fixed_path(path)?;
    ensure!(
        !path.exists() && !path.is_symlink(),
        "Candidate work/output directory already exists; retained outputs are not overwritten"
    );
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn relative(name: &str) -> bool {
    !name.is_empty()
        && name
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
        && !name.chars().any(char::is_control)
        && !name.contains('\\')
        && !name.starts_with('/')
        && Path::new(name)
            .components()
            .all(|p| matches!(p, Component::Normal(_)))
}
fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() <= maximum,
        "Candidate input is not a bounded independent regular file"
    );
    let mut out = Vec::new();
    f.take(maximum + 1).read_to_end(&mut out)?;
    ensure!(
        out.len() as u64 <= maximum,
        "Candidate input grew beyond its bound"
    );
    Ok(out)
}
fn stop(child: &mut std::process::Child) {
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}
fn run(mut command: Command, timeout: Duration, resources: Option<&Resources>) -> Result<Vec<u8>> {
    // Do not pass authentication tokens, loader hooks, compiler wrappers or
    // arbitrary Git/OpenSSL configuration into fixed packaging engines.
    let explicit: Vec<_> = command
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
        .collect();
    command.env_clear();
    for name in [
        "PATH",
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for (name, value) in explicit {
        if [
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_JOBS",
            "CARGO_INCREMENTAL",
            "RUSTFLAGS",
            "CFLAGS",
            "SOURCE_DATE_EPOCH",
        ]
        .iter()
        .any(|n| name == *n)
        {
            command.env(name, value);
        }
    }
    command.env("LANG", "C").env("LC_ALL", "C").env("TZ", "UTC");
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .context("Cannot start fixed candidate build engine")?;
    let exceeded = Arc::new(AtomicBool::new(false));
    fn reader(
        mut s: impl Read + Send + 'static,
        flag: Arc<AtomicBool>,
    ) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
        thread::spawn(move || {
            let mut v = Vec::new();
            (&mut s).take(OUTPUT_LIMIT as u64 + 1).read_to_end(&mut v)?;
            if v.len() > OUTPUT_LIMIT {
                flag.store(true, Ordering::Relaxed);
            }
            Ok(v)
        })
    }
    let out = reader(child.stdout.take().unwrap(), exceeded.clone());
    let err = reader(child.stderr.take().unwrap(), exceeded.clone());
    let start = Instant::now();
    let status = loop {
        if start.elapsed() > timeout
            || exceeded.load(Ordering::Relaxed)
            || resources.is_some_and(|r| r.check().is_err())
        {
            stop(&mut child);
            let _ = out.join();
            let _ = err.join();
            bail!(
                "Candidate engine timed out, exceeded output, or crossed a resource guard; partial work retained"
            );
        }
        if let Some(s) = child.try_wait()? {
            break s;
        }
        thread::sleep(Duration::from_millis(100));
    };
    let bytes = out
        .join()
        .map_err(|_| anyhow::anyhow!("Candidate engine output reader failed"))??;
    let stderr = err
        .join()
        .map_err(|_| anyhow::anyhow!("Candidate engine error reader failed"))??;
    ensure!(
        bytes.len() <= OUTPUT_LIMIT && stderr.len() <= OUTPUT_LIMIT,
        "Candidate engine output exceeded bounds"
    );
    // Never print engine argv or stderr: a signer failure must not expose secret paths.
    ensure!(
        status.success(),
        "Fixed candidate build engine failed; no release was produced"
    );
    Ok(bytes)
}
fn git(source: &Path, args: &[&str]) -> Result<String> {
    let mut c = Command::new("git");
    c.current_dir(source)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args);
    Ok(String::from_utf8(run(c, Duration::from_secs(30), None)?)?)
}
fn cargo(source: &Path, args: &[&str], resources: Option<&Resources>) -> Result<Vec<u8>> {
    let mut c = Command::new("cargo");
    c.current_dir(source)
        .args(args)
        .env("CARGO_BUILD_JOBS", "2");
    run(c, Duration::from_secs(900), resources)
}
fn snapshot(source: &Path) -> Result<Snapshot> {
    fixed_path(source)?;
    ensure!(
        git(source, &["status", "--porcelain", "--untracked-files=all"])?
            .trim()
            .is_empty(),
        "Rust candidate builds require clean committed source"
    );
    let head = git(source, &["rev-parse", "HEAD"])?.trim().to_owned();
    let tree = git(source, &["rev-parse", "HEAD^{tree}"])?
        .trim()
        .to_owned();
    ensure!(
        head.len() == 40 && head.bytes().all(|c| c.is_ascii_hexdigit()),
        "Invalid source commit identity"
    );
    let epoch = git(source, &["show", "-s", "--format=%ct", "HEAD"])?
        .trim()
        .parse::<u64>()?;
    ensure!(
        (315532800..=4102444800).contains(&epoch),
        "Unsupported normalized source epoch"
    );
    let inventory = read_bounded(&source.join("packaging/source-files.json"), MAX_FILE)?;
    let names: Vec<String> = serde_json::from_slice(&inventory)?;
    let tracked = git(source, &["ls-files", "-z"])?;
    let tracked: Vec<_> = tracked.split_terminator('\0').map(str::to_owned).collect();
    ensure!(
        names == tracked && names.windows(2).all(|w| w[0] < w[1]) && names.len() <= MAX_ENTRIES,
        "Source allowlist must exactly equal sorted tracked files"
    );
    let mut total = 0;
    let mut files = Vec::new();
    for name in names {
        ensure!(relative(&name), "Unsafe source archive name");
        ensure!(
            !name.split('/').any(|p| matches!(
                p,
                "private"
                    | "runtime"
                    | ".venv"
                    | ".git"
                    | "node_modules"
                    | "__pycache__"
                    | "target"
            )) && !name.starts_with(".env")
                && !matches!(
                    Path::new(&name).extension().and_then(|x| x.to_str()),
                    Some("sqlite" | "sqlite3" | "db" | "qcow2")
                ),
            "Runtime/private payload is not releasable source"
        );
        let path = source.join(&name);
        ensure!(!path.is_symlink(), "Source links are not packaged");
        for ancestor in path.ancestors().skip(1).take_while(|p| *p != source) {
            ensure!(!ancestor.is_symlink(), "Source path traverses a symlink");
        }
        let bytes = read_bounded(&path, MAX_FILE)?;
        ensure!(
            !String::from_utf8_lossy(&bytes)
                .lines()
                .any(|l| l.starts_with("-----BEGIN ") && l.ends_with("PRIVATE KEY-----")),
            "Private key material is not source"
        );
        total += bytes.len() as u64;
        ensure!(total <= MAX_TOTAL, "Source payload exceeded its bound");
        let indexed = git(source, &["ls-files", "--stage", "--", &name])?;
        let fields: Vec<_> = indexed.split_whitespace().collect();
        ensure!(
            fields.len() >= 4 && fields[2] == "0" && matches!(fields[0], "100644" | "100755"),
            "Unsupported source index entry"
        );
        let raw_hash = git(source, &["hash-object", "--no-filters", "--", &name])?;
        ensure!(
            raw_hash.trim() == fields[1],
            "Source bytes differ from committed Git blob"
        );
        let mode = if fields[0] == "100755" { 0o755 } else { 0o644 };
        ensure!(
            (path.metadata()?.mode() & 0o111 != 0) == (mode == 0o755),
            "Source file mode differs from Git"
        );
        files.push(Input {
            path: name,
            sha256: hash(&bytes),
            size: bytes.len() as u64,
            mode,
        });
    }
    let metadata: serde_json::Value = serde_json::from_slice(&cargo(
        source,
        &[
            "metadata",
            "--locked",
            "--offline",
            "--format-version=1",
            "--no-deps",
        ],
        None,
    )?)?;
    let packages = metadata["packages"]
        .as_array()
        .context("Missing Cargo package metadata")?;
    let p = packages
        .iter()
        .find(|p| p["name"] == "kagnode-daemon")
        .context("Not a Daemon Rust workspace")?;
    let version = p["version"]
        .as_str()
        .context("Missing Rust product version")?
        .to_owned();
    let parts: Vec<_> = version.split('.').collect();
    ensure!(
        parts.len() == 3
            && parts[0] == "5"
            && parts[1] == "0"
            && !parts[2].is_empty()
            && parts[2].bytes().all(|c| c.is_ascii_digit()),
        "Rust product version must stay on 5.0.x"
    );
    Ok(Snapshot {
        head,
        tree,
        epoch,
        version,
        files,
        inventory_sha256: hash(&inventory),
    })
}
fn unchanged(source: &Path, before: &Snapshot) -> Result<()> {
    ensure!(
        git(source, &["rev-parse", "HEAD"])?.trim() == before.head
            && git(source, &["status", "--porcelain", "--untracked-files=all"])?
                .trim()
                .is_empty(),
        "Source identity changed during candidate build"
    );
    for input in &before.files {
        let p = source.join(&input.path);
        ensure!(
            p.metadata()?.len() == input.size && file_hash(&p)? == input.sha256,
            "Source bytes changed during candidate build"
        );
    }
    Ok(())
}
fn target_arch(target: &str) -> Result<(&'static str, u16)> {
    match target {
        "x86_64-unknown-linux-gnu" => Ok(("amd64", 62)),
        "aarch64-unknown-linux-gnu" => Ok(("arm64", 183)),
        _ => bail!("Only explicit Linux GNU amd64/arm64 targets are supported"),
    }
}
fn check_elf(path: &Path, machine: u16) -> Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() > 20 && m.len() <= MAX_FILE,
        "Invalid bounded independent Rust executable"
    );
    let mut b = [0u8; 20];
    (&f).read_exact(&mut b)?;
    ensure!(
        &b[..6] == b"\x7fELF\x02\x01" && u16::from_le_bytes([b[18], b[19]]) == machine,
        "Rust executable has the wrong ELF target"
    );
    Ok(())
}
fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn copy_verified(source: &Path, destination: &Path, input: &Input) -> Result<()> {
    // Validate the bytes actually consumed, not a path checked before a copy.
    let bytes = read_bounded(source, MAX_FILE)?;
    ensure!(
        bytes.len() as u64 == input.size && hash(&bytes) == input.sha256,
        "Candidate input changed before staging"
    );
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write(destination, &bytes, input.mode)
}
fn copy(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    if let Some(p) = destination.parent() {
        std::fs::create_dir_all(p)?;
    }
    ensure!(
        !destination.exists() && !destination.is_symlink(),
        "Candidate payload file already exists"
    );
    // Open with the same nonblocking, no-follow regular-file checks as manifests.
    let bytes = read_bounded(source, MAX_TOTAL)?;
    write(destination, &bytes, mode)
}
fn detach_cargo_output(source: &Path, destination: &Path) -> Result<()> {
    // Cargo hardlinks its own output into its private target root. This narrow
    // internal step admits those links, then creates an independent staged file.
    // No source/download/signing input uses this exception.
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    let metadata = input.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_FILE,
        "Cargo output must be a bounded regular executable"
    );
    let mut bytes = Vec::new();
    input.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE,
        "Cargo output grew beyond bound"
    );
    write(destination, &bytes, 0o755)
}
fn key(fd: i32) -> Result<File> {
    ensure!(
        fd > 2,
        "Supply the existing private signing identity using a read-only inherited descriptor"
    );
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    ensure!(duplicate >= 0, "Signing descriptor is not open");
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    ensure!(
        original_flags >= 0
            && unsafe { libc::fcntl(fd, libc::F_SETFD, original_flags | libc::FD_CLOEXEC) } == 0,
        "Cannot seal inherited signing descriptor"
    );
    let f = File::from(owned);
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.len() <= 16384,
        "Signing descriptor must be a private independent regular file owned by this publisher"
    );
    let flags = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) };
    ensure!(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "Signing descriptor must be read-only"
    );
    Ok(f)
}
fn public_der(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem)?;
    ensure!(
        text.starts_with("-----BEGIN PUBLIC KEY-----\n")
            && text.ends_with("-----END PUBLIC KEY-----\n"),
        "Invalid pinned public key"
    );
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = STANDARD.decode(body)?;
    ensure!(
        der.len() == 44 && der[..12] == [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0],
        "Pinned key must be Ed25519 SubjectPublicKeyInfo"
    );
    Ok(der)
}
fn check_signer(mut f: File) -> Result<()> {
    f.seek(SeekFrom::Start(0))?;
    let mut c = Command::new("openssl");
    c.args(["pkey", "-in", "/dev/stdin", "-pubout", "-outform", "DER"])
        .stdin(Stdio::from(f));
    ensure!(
        run(c, Duration::from_secs(10), None)? == public_der(PUBLIC_KEY)?,
        "Signing identity does not match the established Daemon trust anchor"
    );
    Ok(())
}
fn sign(manifest: &Path, signature: &Path, mut f: File) -> Result<()> {
    f.seek(SeekFrom::Start(0))?;
    let mut c = Command::new("openssl");
    c.args(["pkeyutl", "-sign", "-rawin", "-inkey", "/dev/stdin", "-in"])
        .arg(manifest)
        .arg("-out")
        .arg(signature)
        .stdin(Stdio::from(f));
    run(c, Duration::from_secs(10), None)?;
    Ok(())
}
fn verify_signature(bytes: &[u8], signature: &[u8], pem: &[u8]) -> Result<()> {
    ensure!(signature.len() == 64, "Invalid release signature length");
    let der = public_der(pem)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &der[12..])
        .verify(bytes, signature)
        .map_err(|_| anyhow::anyhow!("Release signature verification failed"))
}
fn artifact(path: &Path, kind: &str) -> Result<Asset> {
    let m = path.metadata()?;
    ensure!(m.len() <= MAX_TOTAL, "Release asset exceeded bound");
    Ok(Asset {
        sha256: file_hash(path)?,
        size: m.len(),
        kind: kind.into(),
    })
}
fn dependency_ids(metadata: &serde_json::Value) -> Result<std::collections::BTreeSet<String>> {
    let packages = metadata["packages"]
        .as_array()
        .context("Missing dependency packages")?;
    let root = packages
        .iter()
        .find(|p| p["name"] == "kagnode-daemon")
        .and_then(|p| p["id"].as_str())
        .context("Missing root package")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .context("Missing dependency graph")?;
    let mut selected = std::collections::BTreeSet::new();
    let mut pending = vec![root.to_owned()];
    while let Some(id) = pending.pop() {
        if !selected.insert(id.clone()) {
            continue;
        }
        let node = nodes
            .iter()
            .find(|n| n["id"] == id)
            .context("Missing resolved dependency")?;
        for d in node["deps"]
            .as_array()
            .context("Missing dependency edges")?
        {
            if d["dep_kinds"]
                .as_array()
                .context("Missing dependency kinds")?
                .iter()
                .any(|k| k["kind"].is_null() || k["kind"] == "build")
            {
                pending.push(
                    d["pkg"]
                        .as_str()
                        .context("Missing dependency package")?
                        .to_owned(),
                );
            }
        }
    }
    Ok(selected)
}
fn licenses(source: &Path, destination: &Path, target: &str) -> Result<()> {
    std::fs::create_dir(destination)?;
    let metadata: serde_json::Value = serde_json::from_slice(&cargo(
        source,
        &[
            "metadata",
            "--locked",
            "--offline",
            "--format-version=1",
            "--filter-platform",
            target,
        ],
        None,
    )?)?;
    let selected = dependency_ids(&metadata)?;
    let mut notices = String::from(
        "Production and build-time Cargo packages reachable from Daemon root; dev-only edges excluded.\nThis is attribution, not a claim every package executes in both binaries.\n\n",
    );
    for package in metadata["packages"]
        .as_array()
        .context("Missing dependency packages")?
    {
        if !selected.contains(package["id"].as_str().context("Missing dependency ID")?) {
            continue;
        }
        let name = package["name"].as_str().context("Missing package name")?;
        let version = package["version"]
            .as_str()
            .context("Missing package version")?;
        ensure!(
            relative(name) && !name.contains('/') && relative(version) && !version.contains('/'),
            "Invalid dependency identity"
        );
        notices += &format!(
            "{name} {version}: {}\n",
            package["license"].as_str().unwrap_or("license-file")
        );
        let root = Path::new(
            package["manifest_path"]
                .as_str()
                .context("Missing dependency path")?,
        )
        .parent()
        .context("Missing dependency root")?;
        let mut files = BTreeMap::new();
        for e in std::fs::read_dir(root)? {
            let e = e?;
            let n = e.file_name();
            let Some(n) = n.to_str() else {
                continue;
            };
            let upper = n.to_ascii_uppercase();
            if ["LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE"]
                .iter()
                .any(|p| upper.starts_with(p))
                && e.file_type()?.is_file()
            {
                files.insert(n.to_owned(), e.path());
            }
        }
        if let Some(n) = package["license_file"].as_str() {
            ensure!(relative(n), "Unsafe declared license path");
            files.insert(n.replace('/', "_"), root.join(n));
        }
        if files.is_empty()
            && root.starts_with(source)
            && name.starts_with("kagnode-")
            && package["license"] == "AGPL-3.0-only"
        {
            files.insert("WORKSPACE-LICENSE".into(), source.join("LICENSE"));
        }
        if files.is_empty() {
            let provenance: serde_json::Value = serde_json::from_slice(&read_bounded(
                &source.join("packaging/rust-license-sources.json"),
                1024 * 1024,
            )?)?;
            ensure!(
                provenance["schema"] == 1,
                "Unknown bundled license provenance schema"
            );
            let entry = provenance["packages"]
                .as_array()
                .context("Missing bundled license records")?
                .iter()
                .find(|p| p["name"] == name && p["version"] == version)
                .context("Missing exact-version dependency license text")?;
            ensure!(
                entry["spdx"] == package["license"],
                "Bundled license identity differs from locked Cargo package"
            );
            for file in entry["files"]
                .as_array()
                .context("Missing bundled license files")?
            {
                let path = file["path"]
                    .as_str()
                    .context("Missing bundled license path")?;
                ensure!(
                    relative(path) && path.starts_with("packaging/third-party-licenses/"),
                    "Unsafe bundled license path"
                );
                ensure!(
                    file_hash(&source.join(path))? == file["sha256"],
                    "Bundled license hash mismatch"
                );
                let name = Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .context("Missing bundled license filename")?;
                ensure!(
                    files.insert(name.to_owned(), source.join(path)).is_none(),
                    "Duplicate bundled license filename"
                );
            }
        }
        ensure!(
            !files.is_empty(),
            "Resolved dependency lacks packaged license text: {name}"
        );
        let target = destination.join(format!("{name}-{version}"));
        std::fs::create_dir(&target)?;
        for (n, path) in files {
            write(
                &target.join(n),
                &read_bounded(&path, 2 * 1024 * 1024)?,
                0o644,
            )?;
        }
    }
    write(&destination.join("INDEX.txt"), notices.as_bytes(), 0o644)?;
    Ok(())
}
fn archive(
    stage: &Path,
    name: &str,
    output: &Path,
    epoch: u64,
    resources: &Resources,
) -> Result<()> {
    let raw = output.with_extension("tar");
    let mut c = Command::new("tar");
    c.current_dir(stage)
        .args([
            "--format=ustar",
            "--sort=name",
            "--numeric-owner",
            "--owner=0",
            "--group=0",
            "--mode=u+rwX,go+rX,go-w",
        ])
        .arg(format!("--mtime=@{epoch}"))
        .arg("-cf")
        .arg(&raw)
        .arg("--")
        .arg(name);
    run(c, Duration::from_secs(120), Some(resources))?;
    validate_tar(&mut File::open(&raw)?)?;
    let mut c = Command::new("gzip");
    c.args(["-n", "-9", "--"]).arg(&raw);
    run(c, Duration::from_secs(120), Some(resources))?;
    std::fs::rename(raw.with_extension("tar.gz"), output)?;
    Ok(())
}
fn octal(b: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(b)?.trim_matches(['\0', ' ']);
    if s.is_empty() {
        return Ok(0);
    }
    ensure!(
        s.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        "Invalid tar numeric field"
    );
    Ok(u64::from_str_radix(s, 8)?)
}
fn field(b: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(&b[..b.iter().position(|b| *b == 0).unwrap_or(b.len())])?.to_owned())
}
fn validate_tar(reader: &mut impl Read) -> Result<()> {
    let mut count = 0;
    let mut total: u64 = 0;
    let mut names = std::collections::BTreeSet::new();
    let mut root = None;
    loop {
        let mut h = [0u8; 512];
        reader.read_exact(&mut h)?;
        if h.iter().all(|b| *b == 0) {
            let mut trailer = Vec::new();
            (&mut *reader).take(65537).read_to_end(&mut trailer)?;
            ensure!(
                (512..=65536).contains(&trailer.len()) && trailer.iter().all(|b| *b == 0),
                "Invalid or hidden archive trailer"
            );
            break;
        }
        let expected = octal(&h[148..156])?;
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        ensure!(sum == expected, "Tar checksum mismatch");
        ensure!(
            matches!(h[156], 0 | b'0' | b'5') && h[157..257].iter().all(|b| *b == 0),
            "Archive links and special files are forbidden"
        );
        let prefix = field(&h[345..500])?;
        let name = field(&h[..100])?;
        let name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let normalized = name.trim_end_matches('/');
        ensure!(
            relative(normalized) && names.insert(normalized.to_owned()),
            "Unsafe or duplicate tar member"
        );
        let top = normalized.split('/').next().unwrap().to_owned();
        if let Some(r) = &root {
            ensure!(
                r == &top,
                "Archive must have exactly one top-level directory"
            );
        } else {
            root = Some(top);
        }
        let size = octal(&h[124..136])?;
        ensure!(size <= MAX_FILE, "Tar member exceeds bound");
        total = total.checked_add(size).context("Tar size overflow")?;
        count += 1;
        ensure!(
            count <= MAX_ENTRIES && total <= MAX_TOTAL,
            "Expanded archive exceeds count/byte bounds"
        );
        ensure!(h[156] != b'5' || size == 0, "Archive directory has payload");
        let mut skip = reader.take(size.div_ceil(512) * 512);
        std::io::copy(&mut skip, &mut std::io::sink())?;
        ensure!(skip.limit() == 0, "Truncated archive payload");
    }
    ensure!(count > 0, "Empty archive");
    Ok(())
}
fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir(destination)?;
    let mut queue =
        std::collections::VecDeque::from([(source.to_path_buf(), destination.to_path_buf())]);
    let mut count = 0usize;
    let mut bytes = 0u64;
    while let Some((from, to)) = queue.pop_front() {
        for entry in std::fs::read_dir(&from)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            count += 1;
            ensure!(
                count <= MAX_ENTRIES && !kind.is_symlink(),
                "Unsafe license tree"
            );
            let target = to.join(entry.file_name());
            if kind.is_dir() {
                std::fs::create_dir(&target)?;
                queue.push_back((entry.path(), target));
            } else {
                let data = read_bounded(&entry.path(), MAX_FILE)?;
                bytes += data.len() as u64;
                ensure!(bytes <= MAX_TOTAL, "License tree exceeded bounds");
                write(&target, &data, 0o644)?;
            }
        }
    }
    Ok(())
}

// Reject duplicate members before typed deserialization, including asset maps.
fn unique_json(bytes: &[u8]) -> Result<serde_json::Value> {
    struct Unique(serde_json::Value);
    impl<'de> serde::Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("JSON with unique members")
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_string<E: serde::de::Error>(
                    self,
                    v: String,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(serde_json::Value::Null))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut values = Vec::new();
                    while let Some(x) = a.next_element::<Unique>()? {
                        values.push(x.0);
                    }
                    Ok(Unique(values.into()))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some((key, x)) = a.next_entry::<String, Unique>()? {
                        if values.insert(key, x.0).is_some() {
                            return Err(serde::de::Error::custom("duplicate JSON object member"));
                        }
                    }
                    Ok(Unique(values.into()))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    Ok(serde_json::from_slice::<Unique>(bytes)?.0)
}

struct PackageContext<'a> {
    source: &'a Path,
    snap: &'a Snapshot,
    target: &'a str,
    fd: i32,
    resources: &'a Resources,
    rustc: &'a str,
    binaries: &'a BTreeMap<String, String>,
}
fn package(context: &PackageContext<'_>, build: &Path, work: &Path, output: &Path) -> Result<()> {
    let source = context.source;
    let snap = context.snap;
    let target = context.target;
    let fd = context.fd;
    let resources = context.resources;
    let rustc = context.rustc;
    private_new_directory(work)?;
    private_new_directory(output)?;
    let stage = work.join("stage");
    std::fs::create_dir(&stage)?;
    let source_name = format!("kagnode-daemon_{}_source", snap.version);
    let src = stage.join(&source_name);
    std::fs::create_dir(&src)?;
    for f in &snap.files {
        copy_verified(&source.join(&f.path), &src.join(&f.path), f)?;
    }
    let (arch, machine) = target_arch(target)?;
    let native_name = format!("kagnode-daemon_{}_linux_{arch}", snap.version);
    let native = stage.join(&native_name);
    std::fs::create_dir(&native)?;
    std::fs::create_dir(native.join("bin"))?;
    let mut bins = BTreeMap::new();
    for name in BINARIES {
        let binary = build.join(target).join("release").join(name);
        let admitted = native.join("bin").join(name);
        let identity = Input {
            path: (*name).into(),
            sha256: context
                .binaries
                .get(*name)
                .context("Missing repeated binary hash")?
                .clone(),
            size: binary.metadata()?.len(),
            mode: 0o755,
        };
        copy_verified(&binary, &admitted, &identity)?;
        check_elf(&admitted, machine)?;
        bins.insert((*name).into(), artifact(&admitted, "rust-executable")?);
    }
    for name in ["LICENSE", "BRAND-POLICY.md", "ARTWORK-LICENSE"] {
        copy(&source.join(name), &native.join(name), 0o644)?;
    }
    write(
        &native.join("SOURCE-COMMIT"),
        format!("{}\n", snap.head).as_bytes(),
        0o644,
    )?;
    licenses(source, &native.join("licenses"), target)?;
    archive(
        &stage,
        &source_name,
        &output.join(format!("{source_name}.tar.gz")),
        snap.epoch,
        resources,
    )?;
    archive(
        &stage,
        &native_name,
        &output.join(format!("{native_name}.tar.gz")),
        snap.epoch,
        resources,
    )?;
    let debroot = work.join("deb");
    let payload = debroot
        .join("usr/libexec/kagnode-daemon/releases")
        .join(&snap.version);
    std::fs::create_dir_all(payload.join("bin"))?;
    for name in BINARIES {
        copy(
            &native.join("bin").join(name),
            &payload.join("bin").join(name),
            0o755,
        )?;
    }
    let documentation = debroot.join("usr/share/doc/kagnode-daemon");
    std::fs::create_dir_all(&documentation)?;
    copy(
        &native.join("LICENSE"),
        &documentation.join("copyright"),
        0o644,
    )?;
    for name in ["BRAND-POLICY.md", "ARTWORK-LICENSE", "SOURCE-COMMIT"] {
        copy(&native.join(name), &documentation.join(name), 0o644)?;
    }
    copy_tree(&native.join("licenses"), &documentation.join("licenses"))?;
    let control = debroot.join("DEBIAN");
    std::fs::create_dir(&control)?;
    let package_version = format!("{}+rustcandidate.g{}", snap.version, &snap.head[..12]);
    write(&control.join("control"),format!("Package: kagnode-daemon\nVersion: {package_version}\nArchitecture: {arch}\nMaintainer: KagNode maintainers\nSection: admin\nPriority: optional\nDepends: libc6 (>= 2.39), libgcc-s1, ca-certificates\nDescription: KagNode Rust Daemon candidate payload; activation is separate\n No service setup, command replacement, account creation or data migration.\n Native installation and production qualification remain separate gates.\n").as_bytes(),0o644)?;
    let deb = output.join(format!("kagnode-daemon_{}_{}.deb", snap.version, arch));
    let mut c = Command::new("dpkg-deb");
    c.args([
        "--root-owner-group",
        "--uniform-compression",
        "-Zxz",
        "-z6",
        "--build",
    ])
    .arg(&debroot)
    .arg(&deb)
    .env("SOURCE_DATE_EPOCH", snap.epoch.to_string());
    run(c, Duration::from_secs(120), Some(resources))?;
    let mut assets = BTreeMap::new();
    for p in std::fs::read_dir(output)? {
        let p = p?.path();
        let name = p
            .file_name()
            .unwrap()
            .to_str()
            .context("Invalid asset name")?
            .to_owned();
        assets.insert(
            name,
            artifact(
                &p,
                if p.extension().is_some_and(|s| s == "deb") {
                    "native-candidate-package"
                } else if p.file_name().unwrap().to_string_lossy().contains("_source") {
                    "source-data-archive"
                } else {
                    "native-candidate-archive"
                },
            )?,
        );
    }
    let manifest = Manifest {
        schema: 1,
        repository: "every-lemon/kagnode-daemon".into(),
        version: snap.version.clone(),
        product_version: snap.version.clone(),
        source_commit: snap.head.clone(),
        source_tree: snap.tree.clone(),
        epoch: snap.epoch,
        runtime: "rust".into(),
        target: target.into(),
        channel: "preview".into(),
        native_qualification: "unqualified-candidate; no production publication or activation"
            .into(),
        production_eligible: false,
        rustc: rustc.into(),
        binaries: bins,
        assets,
        source_inventory_sha256: snap.inventory_sha256.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    write(&output.join("release-manifest.json"), &bytes, 0o644)?;
    write(&output.join("release-public.pem"), PUBLIC_KEY, 0o644)?;
    sign(
        &output.join("release-manifest.json"),
        &output.join("release-manifest.sig"),
        key(fd)?,
    )?;
    verify(output)?;
    let mut sums = String::new();
    let mut files: Vec<_> = std::fs::read_dir(output)?
        .map(|p| p.map(|p| p.path()))
        .collect::<std::io::Result<_>>()?;
    files.sort();
    for p in files {
        sums += &format!(
            "{}  {}\n",
            file_hash(&p)?,
            p.file_name().unwrap().to_string_lossy()
        );
    }
    write(&output.join("SHA256SUMS"), sums.as_bytes(), 0o644)?;
    File::open(output)?.sync_all()?;
    Ok(())
}
/// Builds two independent clean Rust targets and two normalized, signed payloads.
/// An inherited read-only private-key descriptor signs candidates; no secret is an argument.
pub fn build(options: &BuildOptions) -> Result<serde_json::Value> {
    let (arch, machine) = target_arch(&options.target)?;
    ensure!(
        (arch == "amd64" && std::env::consts::ARCH == "x86_64")
            || (arch == "arm64" && std::env::consts::ARCH == "aarch64"),
        "Native qualification builds must run on their stated target architecture"
    );
    fixed_path(&options.source)?;
    fixed_path(&options.work)?;
    fixed_path(&options.output)?;
    ensure!(
        !options.work.starts_with(&options.source)
            && !options.output.starts_with(&options.source)
            && !options.output.starts_with(&options.work)
            && !options.work.starts_with(&options.output),
        "Separate source, work and output directories"
    );
    let resource = Resources::new(options.work.parent().context("Missing build parent")?)?;
    check_signer(key(options.signing_fd)?)?;
    let snap = snapshot(&options.source)?;
    private_new_directory(&options.work)?;
    private_new_directory(&options.output)?;
    let mut c = Command::new("rustc");
    c.arg("--version");
    let rustc = String::from_utf8(run(c, Duration::from_secs(10), None)?)?
        .trim()
        .to_owned();
    let first = options.work.join("target-first");
    let second = options.work.join("target-second");
    let flags = format!(
        "--remap-path-prefix={}=/kagnode-source --remap-path-prefix={}=/kagnode-target --remap-path-prefix={}=/kagnode-target -C debuginfo=0 -C link-arg=-Wl,--build-id=none",
        options.source.display(),
        first.display(),
        second.display()
    );
    let cflags = format!(
        "-fdebug-prefix-map={}=/kagnode-source -fmacro-prefix-map={}=/kagnode-source -fdebug-prefix-map={}=/kagnode-target -fmacro-prefix-map={}=/kagnode-target -fdebug-prefix-map={}=/kagnode-target -fmacro-prefix-map={}=/kagnode-target",
        options.source.display(),
        options.source.display(),
        first.display(),
        first.display(),
        second.display(),
        second.display()
    );
    let mut observed = Vec::new();
    for dir in [&first, &second] {
        ensure!(!dir.exists(), "Target directory must start absent");
        let mut c = Command::new("cargo");
        c.current_dir(&options.source)
            .args([
                "build",
                "--release",
                "--locked",
                "--offline",
                "--bin",
                "kagnode",
                "--bin",
                "kagnode-backup-server",
                "--target",
            ])
            .arg(&options.target)
            .env("CARGO_TARGET_DIR", dir)
            .env("CARGO_BUILD_JOBS", "2")
            .env("CARGO_INCREMENTAL", "0")
            .env("RUSTFLAGS", &flags)
            .env("CFLAGS", &cflags)
            .env("SOURCE_DATE_EPOCH", snap.epoch.to_string());
        run(c, Duration::from_secs(1800), Some(&resource))?;
        let mut hashes = BTreeMap::new();
        for name in BINARIES {
            let p = dir.join(&options.target).join("release").join(name);
            let independent = p.with_extension("independent");
            detach_cargo_output(&p, &independent)?;
            std::fs::rename(&independent, &p)?;
            check_elf(&p, machine)?;
            let mut c = Command::new(&p);
            c.arg("--version");
            let version = String::from_utf8(run(c, Duration::from_secs(10), None)?)?;
            ensure!(
                version.split_whitespace().last() == Some(snap.version.as_str()),
                "Rust executable version differs from source"
            );
            hashes.insert((*name).to_owned(), file_hash(&p)?);
        }
        observed.push(hashes);
        let progress = serde_json::json!({"source":snap.head,"target":options.target,"rustc":rustc,"clean_build_count":observed.len(),"binaries":observed,"production_eligible":false});
        let progress_path = options.work.join("build-observations.json");
        let next = options.work.join(".build-observations.next");
        write(&next, &serde_json::to_vec_pretty(&progress)?, 0o600)?;
        std::fs::rename(next, progress_path)?;
        unchanged(&options.source, &snap)?;
    }
    ensure!(
        observed[0] == observed[1],
        "Independent clean Rust binary builds differ; no package signed"
    );
    let one = options.work.join("packages-first");
    let two = options.work.join("packages-repeat");
    let context = PackageContext {
        source: &options.source,
        snap: &snap,
        target: &options.target,
        fd: options.signing_fd,
        resources: &resource,
        rustc: &rustc,
        binaries: &observed[0],
    };
    package(
        &context,
        &first,
        &options.work.join("package-work-first"),
        &one,
    )?;
    package(
        &context,
        &second,
        &options.work.join("package-work-repeat"),
        &two,
    )?;
    let a = directory_hashes(&one)?;
    ensure!(
        a == directory_hashes(&two)?,
        "Repeat normalized signed packages differ; outputs not activated"
    );
    unchanged(&options.source, &snap)?;
    for name in a.keys() {
        copy(&one.join(name), &options.output.join(name), 0o644)?;
    }
    verify(&options.output)?;
    File::open(&options.output)?.sync_all()?;
    Ok(
        serde_json::json!({"source":snap.head,"tree":snap.tree,"version":snap.version,"runtime":"rust","target":options.target,"two_independent_clean_binary_builds_identical":true,"binaries":observed[0],"repeat_signed_packages_identical":true,"assets":a,"output":options.output,"production_eligible":false,"published":false,"installed":false,"legacy_command_changed":false}),
    )
}
fn directory_hashes(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for p in std::fs::read_dir(path)? {
        let p = p?.path();
        ensure!(p.is_file() && !p.is_symlink(), "Unexpected release output");
        let n = p
            .file_name()
            .unwrap()
            .to_str()
            .context("Invalid release output name")?
            .to_owned();
        ensure!(
            relative(&n) && !n.contains('/'),
            "Unsafe release output name"
        );
        out.insert(n, file_hash(&p)?);
    }
    Ok(out)
}
/// Verify signed bytes against the compiled established key, never a supplied download key.
pub fn verify(folder: &Path) -> Result<Manifest> {
    fixed_path(folder)?;
    let bytes = read_bounded(&folder.join("release-manifest.json"), 1024 * 1024)?;
    let sig = read_bounded(&folder.join("release-manifest.sig"), 1024)?;
    verify_signature(&bytes, &sig, PUBLIC_KEY)?;
    let m: Manifest = serde_json::from_value(unique_json(&bytes)?)?;
    ensure!(
        m.schema == 1
            && m.repository == "every-lemon/kagnode-daemon"
            && m.runtime == "rust"
            && m.channel == "preview"
            && !m.production_eligible,
        "Manifest is not an explicitly unqualified Rust candidate"
    );
    target_arch(&m.target)?;
    ensure!(
        m.source_commit.len() == 40
            && m.source_commit.bytes().all(|c| c.is_ascii_hexdigit())
            && m.source_tree.len() == 40
            && m.source_tree.bytes().all(|c| c.is_ascii_hexdigit()),
        "Invalid release source identity"
    );
    ensure!(
        m.binaries.len() == BINARIES.len()
            && BINARIES.iter().all(|n| m.binaries.contains_key(*n))
            && !m.assets.is_empty()
            && m.assets.len() <= 32,
        "Invalid bounded candidate asset selection"
    );
    let (arch, _) = target_arch(&m.target)?;
    let parts: Vec<_> = m.version.split('.').collect();
    ensure!(
        parts.len() == 3
            && parts[0] == "5"
            && parts[1] == "0"
            && !parts[2].is_empty()
            && parts[2].bytes().all(|b| b.is_ascii_digit())
            && m.version.len() <= 32
            && m.product_version == m.version,
        "Invalid candidate product version"
    );
    let expected = BTreeMap::from([
        (
            format!("kagnode-daemon_{}_source.tar.gz", m.version),
            "source-data-archive",
        ),
        (
            format!("kagnode-daemon_{}_linux_{arch}.tar.gz", m.version),
            "native-candidate-archive",
        ),
        (
            format!("kagnode-daemon_{}_{arch}.deb", m.version),
            "native-candidate-package",
        ),
    ]);
    ensure!(
        m.assets.len() == expected.len()
            && expected
                .iter()
                .all(|(name, kind)| m.assets.get(name).is_some_and(|a| a.kind == *kind)),
        "Unexpected candidate payload selection/kind"
    );
    for (name, asset) in &m.assets {
        ensure!(
            relative(name)
                && !name.contains('/')
                && asset.size <= MAX_TOTAL
                && asset.sha256.len() == 64,
            "Unsafe or invalid signed asset"
        );
        let p = folder.join(name);
        let data = read_bounded(&p, MAX_TOTAL)?;
        ensure!(
            data.len() as u64 == asset.size && hash(&data) == asset.sha256,
            "Candidate payload hash/size mismatch"
        );
    }
    let found = directory_hashes(folder)?;
    let mut names: std::collections::BTreeSet<_> = m.assets.keys().map(String::as_str).collect();
    names.extend([
        "release-manifest.json",
        "release-manifest.sig",
        "release-public.pem",
    ]);
    if found.contains_key("SHA256SUMS") {
        names.insert("SHA256SUMS");
    }
    ensure!(
        found
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == names,
        "Unexpected file in candidate release"
    );
    ensure!(
        read_bounded(&folder.join("release-public.pem"), 1024)? == PUBLIC_KEY,
        "Downloaded key differs from compiled trust anchor"
    );
    if let Ok(sums) = std::fs::read_to_string(folder.join("SHA256SUMS")) {
        let expected: String = found
            .iter()
            .filter(|(name, _)| name.as_str() != "SHA256SUMS")
            .map(|(name, h)| format!("{h}  {name}\n"))
            .collect();
        ensure!(
            sums == expected,
            "Candidate checksum file differs from verified contents"
        );
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_targets_are_closed() {
        for p in [
            "../x", "/x", "a//../b", "a\\b", "a\nb", "", "a/./b", "a//b", "a/",
        ] {
            assert!(!relative(p));
        }
        assert!(relative("src/main.rs"));
        assert!(target_arch("host").is_err());
    }
    #[test]
    fn unsafe_output_path_and_reuse_are_rejected() -> Result<()> {
        let t = tempfile::tempdir()?;
        let p = t.path().join("new");
        private_new_directory(&p)?;
        assert!(private_new_directory(&p).is_err());
        let l = t.path().join("link");
        std::os::unix::fs::symlink(&p, &l)?;
        assert!(fixed_path(&l).is_err());
        Ok(())
    }
    #[test]
    fn input_links_and_oversize_are_rejected() -> Result<()> {
        let t = tempfile::tempdir()?;
        let p = t.path().join("input");
        write(&p, b"abc", 0o600)?;
        assert!(read_bounded(&p, 2).is_err());
        let l = t.path().join("linked");
        std::fs::hard_link(&p, &l)?;
        assert!(read_bounded(&p, 20).is_err());
        let s = t.path().join("symlink");
        std::os::unix::fs::symlink(&p, &s)?;
        assert!(read_bounded(&s, 20).is_err());
        Ok(())
    }
    #[test]
    fn wrong_and_missing_signatures_fail() {
        assert!(verify_signature(b"manifest", &[0; 64], PUBLIC_KEY).is_err());
        assert!(verify_signature(b"manifest", b"", PUBLIC_KEY).is_err());
        assert!(public_der(b"downloaded untrusted key").is_err());
    }
    #[test]
    fn duplicate_members_are_rejected_recursively() {
        assert!(unique_json(br#"{"assets":{"same":1,"same":2}}"#).is_err());
        assert!(unique_json(br#"{"schema":1,"schema":1}"#).is_err());
        assert!(unique_json(br#"{"assets":{"one":1,"two":2}}"#).is_ok());
    }
    #[test]
    fn correct_signature_tampering_and_wrong_key() -> Result<()> {
        use ring::signature::KeyPair;
        let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32])
            .map_err(|_| anyhow::anyhow!("fixture key"))?;
        let mut der = vec![48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0];
        der.extend(signer.public_key().as_ref());
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        );
        let sig = signer.sign(b"candidate");
        verify_signature(b"candidate", sig.as_ref(), pem.as_bytes())?;
        assert!(verify_signature(b"tampered", sig.as_ref(), pem.as_bytes()).is_err());
        assert!(verify_signature(b"candidate", sig.as_ref(), PUBLIC_KEY).is_err());
        Ok(())
    }
    #[test]
    fn dirty_source_is_rejected_before_build() -> Result<()> {
        let t = tempfile::tempdir()?;
        let mut c = Command::new("git");
        c.current_dir(t.path()).args(["init", "-q"]);
        run(c, Duration::from_secs(10), None)?;
        write(&t.path().join("untracked"), b"fixture", 0o600)?;
        assert!(
            snapshot(t.path())
                .unwrap_err()
                .to_string()
                .contains("clean committed")
        );
        Ok(())
    }
    #[test]
    fn signing_descriptor_must_be_private_read_only() -> Result<()> {
        assert!(key(-1).is_err());
        assert!(key(0).is_err());
        assert!(key(999999).is_err());
        let t = tempfile::tempdir()?;
        let p = t.path().join("key");
        write(&p, b"not-a-key", 0o644)?;
        let f = File::open(&p)?;
        assert!(key(f.as_raw_fd()).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        let f = OpenOptions::new().read(true).write(true).open(&p)?;
        assert!(key(f.as_raw_fd()).is_err());
        Ok(())
    }
    #[test]
    fn private_signer_is_not_inherited_by_build_engines() -> Result<()> {
        let t = tempfile::tempdir()?;
        let p = t.path().join("fixture-key");
        write(&p, b"synthetic fixture only", 0o600)?;
        let f = File::open(p)?;
        let owned = key(f.as_raw_fd())?;
        drop(owned);
        let mut command = Command::new("/usr/bin/test");
        command
            .args(["!", "-e"])
            .arg(format!("/proc/self/fd/{}", f.as_raw_fd()));
        run(command, Duration::from_secs(5), None)?;
        Ok(())
    }
    #[test]
    fn signing_with_a_different_private_identity_is_refused() -> Result<()> {
        let t = tempfile::tempdir()?;
        let p = t.path().join("fixture-key");
        // OpenSSL's accepted PKCS#8 encoding is the signer input format;
        // ring's generated v2 encoding is not accepted by every supported engine.
        let mut command = Command::new("openssl");
        command.args(["genpkey", "-algorithm", "ED25519"]);
        let pem = run(command, Duration::from_secs(10), None)?;
        write(&p, &pem, 0o600)?;
        let f = File::open(p)?;
        assert!(
            check_signer(key(f.as_raw_fd())?)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
        Ok(())
    }
    #[test]
    fn packaging_engines_do_not_receive_arbitrary_environment() -> Result<()> {
        let mut command = Command::new("/usr/bin/env");
        command
            .env("KAGNODE_FIXTURE_SECRET", "synthetic-only")
            .env("LD_PRELOAD", "invalid-fixture");
        let output = String::from_utf8(run(command, Duration::from_secs(5), None)?)?;
        assert!(!output.contains("KAGNODE_FIXTURE_SECRET") && !output.contains("LD_PRELOAD="));
        Ok(())
    }
    fn fifo_refused_promptly(reader: fn(&Path) -> Result<()>) -> Result<()> {
        let t = tempfile::tempdir()?;
        let path = t.path().join("untrusted-input");
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        ensure!(
            unsafe { libc::mkfifo(name.as_ptr(), 0o600) } == 0,
            "fixture fifo"
        );
        let (send, receive) = std::sync::mpsc::channel();
        let input = path.clone();
        let worker = std::thread::spawn(move || {
            let _ = send.send(reader(&input).is_err());
        });
        let timely = receive.recv_timeout(Duration::from_millis(500)).ok();
        if timely.is_none() {
            // Let a blocking old reader finish, so the failing regression cannot
            // leave a hung test process or FIFO descriptor behind.
            let writer = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path)?;
            drop(writer);
            let _ = receive.recv_timeout(Duration::from_secs(2));
        }
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("fixture reader panic"))?;
        ensure!(
            timely == Some(true),
            "FIFO input blocked before regular-file admission"
        );
        Ok(())
    }
    #[test]
    fn fifo_manifest_input_is_refused_without_waiting_for_writer() -> Result<()> {
        fifo_refused_promptly(|p| read_bounded(p, 1024).map(|_| ()))
    }
    #[test]
    fn fifo_hash_input_is_refused_without_waiting_for_writer() -> Result<()> {
        fifo_refused_promptly(|p| file_hash(p).map(|_| ()))
    }
    #[test]
    fn cargo_link_detachment_is_narrow_and_independent() -> Result<()> {
        let t = tempfile::tempdir()?;
        let input = t.path().join("cargo-output");
        write(&input, b"synthetic cargo output", 0o755)?;
        std::fs::hard_link(&input, t.path().join("cargo-internal-link"))?;
        assert!(read_bounded(&input, MAX_FILE).is_err());
        let staged = t.path().join("independent");
        detach_cargo_output(&input, &staged)?;
        assert_eq!(staged.metadata()?.nlink(), 1);
        assert_eq!(read_bounded(&staged, MAX_FILE)?, b"synthetic cargo output");
        Ok(())
    }
    #[test]
    fn wrong_elf_target_fails() -> Result<()> {
        let t = tempfile::tempdir()?;
        let p = t.path().join("bin");
        let mut data = vec![0u8; 64];
        data[..6].copy_from_slice(b"\x7fELF\x02\x01");
        data[18..20].copy_from_slice(&183u16.to_le_bytes());
        write(&p, &data, 0o755)?;
        assert!(check_elf(&p, 62).is_err());
        check_elf(&p, 183)?;
        Ok(())
    }
    #[test]
    fn command_timeout_is_bounded() {
        let mut c = Command::new("/bin/sleep");
        c.arg("5");
        let start = Instant::now();
        assert!(run(c, Duration::from_millis(50), None).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn runaway_engine_output_is_bounded() {
        let mut command = Command::new("/usr/bin/yes");
        command.arg("bounded-fixture");
        let start = Instant::now();
        assert!(run(command, Duration::from_secs(5), None).is_err());
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn source_changes_after_snapshot_are_rejected() -> Result<()> {
        let t = tempfile::tempdir()?;
        let mut command = Command::new("git");
        command.current_dir(t.path()).args(["init", "-q"]);
        run(command, Duration::from_secs(10), None)?;
        write(&t.path().join("input"), b"before", 0o644)?;
        let mut command = Command::new("git");
        command.current_dir(t.path()).args(["add", "input"]);
        run(command, Duration::from_secs(10), None)?;
        let mut command = Command::new("git");
        command.current_dir(t.path()).args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@invalid",
            "commit",
            "--no-gpg-sign",
            "-qm",
            "fixture",
        ]);
        run(command, Duration::from_secs(10), None)?;
        let s = Snapshot {
            head: git(t.path(), &["rev-parse", "HEAD"])?.trim().into(),
            tree: String::new(),
            epoch: 0,
            version: "5.0.3".into(),
            files: vec![Input {
                path: "input".into(),
                sha256: hash(b"before"),
                size: 6,
                mode: 0o644,
            }],
            inventory_sha256: String::new(),
        };
        unchanged(t.path(), &s)?;
        std::fs::write(t.path().join("input"), b"after!")?;
        assert!(unchanged(t.path(), &s).is_err());
        Ok(())
    }
    #[test]
    fn staging_checks_actual_consumed_bytes() -> Result<()> {
        let t = tempfile::tempdir()?;
        let source = t.path().join("input");
        write(&source, b"original", 0o644)?;
        let input = Input {
            path: "input".into(),
            sha256: hash(b"original"),
            size: 8,
            mode: 0o644,
        };
        copy_verified(&source, &t.path().join("accepted"), &input)?;
        std::fs::write(&source, b"modified")?;
        assert!(copy_verified(&source, &t.path().join("refused"), &input).is_err());
        assert!(!t.path().join("refused").exists());
        Ok(())
    }
    #[test]
    fn legacy_tag_publisher_is_disabled_and_rust_ci_has_no_publisher() {
        let old = include_str!("../.github/workflows/packaging.yml");
        let new = include_str!("../.github/workflows/rust-release.yml");
        assert!(old.contains("if: ${{ false }}"));
        assert!(!new.contains("contents: write") && !new.contains("gh release create"));
    }
    fn header(name: &str, kind: u8, size: u64) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let n = format!("{size:011o}\0");
        h[124..136].copy_from_slice(n.as_bytes());
        h[156] = kind;
        h[148..156].fill(b' ');
        let checksum: u64 = h.iter().map(|b| *b as u64).sum();
        h[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        h
    }
    #[test]
    fn tar_rejects_links_traversal_duplicates_and_truncation() {
        for (name, kind) in [("../x", b'0'), ("root/link", b'2'), ("/root/x", b'0')] {
            let mut data = header(name, kind, 0).to_vec();
            data.extend([0; 512]);
            assert!(validate_tar(&mut data.as_slice()).is_err());
        }
        let mut duplicate = header("root/file", b'0', 0).to_vec();
        duplicate.extend(header("root/file", b'0', 0));
        duplicate.extend([0; 512]);
        assert!(validate_tar(&mut duplicate.as_slice()).is_err());
        let data = header("root/file", b'0', 20);
        assert!(validate_tar(&mut data.as_slice()).is_err());
    }
    #[test]
    fn tar_requires_one_root_and_accepts_regular_files() {
        let mut data = header("root", b'5', 0).to_vec();
        data.extend(header("root/a", b'0', 3));
        data.extend(b"abc");
        data.extend([0; 509]);
        data.extend([0; 512]);
        data.extend([0; 512]);
        assert!(validate_tar(&mut data.as_slice()).is_ok());
        let mut data = header("root/a", b'0', 0).to_vec();
        data.extend(header("other/b", b'0', 0));
        data.extend([0; 512]);
        assert!(validate_tar(&mut data.as_slice()).is_err());
    }
    #[test]
    fn archive_cannot_hide_members_after_end_marker() {
        let mut data = header("root", b'5', 0).to_vec();
        data.extend([0; 512]);
        data.extend(header("root/hidden", b'0', 0));
        data.extend([0; 1024]);
        assert!(validate_tar(&mut data.as_slice()).is_err());
    }
    #[test]
    fn license_graph_excludes_dev_only_but_keeps_build_edges() -> Result<()> {
        let m = serde_json::json!({"packages":[{"name":"kagnode-daemon","id":"root"}],"resolve":{"nodes":[
            {"id":"root","deps":[{"pkg":"normal","dep_kinds":[{"kind":null}]},{"pkg":"build","dep_kinds":[{"kind":"build"}]},{"pkg":"dev","dep_kinds":[{"kind":"dev"}]}]},
            {"id":"normal","deps":[]},{"id":"build","deps":[]},{"id":"dev","deps":[]}
        ]}});
        assert_eq!(
            dependency_ids(&m)?,
            ["root".into(), "normal".into(), "build".into()].into()
        );
        Ok(())
    }
    #[test]
    fn output_directory_hashes_detect_changed_bytes() -> Result<()> {
        let t = tempfile::tempdir()?;
        let p = t.path().join("file");
        write(&p, b"before", 0o600)?;
        let a = directory_hashes(t.path())?;
        std::fs::write(p, b"after")?;
        assert_ne!(a, directory_hashes(t.path())?);
        Ok(())
    }
}
