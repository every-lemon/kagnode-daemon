//! Read-only legacy inventory and synthetic COPY rehearsal. Activation is unavailable.
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::MetadataExt,
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const OLD: &str = "srv/kagnode/cli/releases/5.0.2-reviewed/kagnode";
const ENTRY: &str = "usr/bin/kagnode";
const KNOWN: &str = "123a036a3112271ed86245650110fbb908e56da5378d40eb5f53093d713daf85";
const FIXTURE: &[u8] = b"KagNode synthetic legacy fixture v1\n";
const DATA: [&str; 2] = [
    "srv/kagnode/manager.json",
    "srv/kagnode/proxy-manager/state.json",
];
const UNITS: [&str; 2] = ["kagnode-core.service", "kagnode-updates.service"];
const NEW_UNITS: [&str; 8] = [
    "kagnode-daemon.service",
    "kagnode-controller.service",
    "kagnode-broker.service",
    "kagnode-daemon-broker.service",
    "kagnode-daemon-monitor.service",
    "kagnode-daemon-monitor.timer",
    "kagnode-daemon-backup.service",
    "kagnode-daemon-backup.timer",
];
const MAX: u64 = 64 * 1024 * 1024;
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn root() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "legacy_root_required");
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileState {
    pub dev: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub bytes: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub ctime: i64,
    pub ctime_ns: i64,
    pub sha256: String,
}
fn state(m: &std::fs::Metadata, b: &[u8]) -> FileState {
    FileState {
        dev: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        bytes: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
        sha256: hash(b),
    }
}
// Every component is opened relative to an already-checked descriptor; neither
// symlink traversal nor a concurrently replaced parent can redirect an open.
fn directory(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "legacy_absolute_path_required");
    let mut d = File::open("/")?;
    for c in path.components() {
        match c {
            Component::RootDir => (),
            Component::Normal(n) => {
                d = openat(
                    &d,
                    n.to_str()
                        .ok_or_else(|| anyhow::anyhow!("legacy_non_utf8"))?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
            }
            _ => bail!("legacy_noncanonical_path"),
        }
        check_dir(&d)?;
    }
    check_dir(&d)?;
    Ok(d)
}
fn check_dir(d: &File) -> Result<()> {
    let m = d.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "legacy_unsafe_directory"
    );
    Ok(())
}
fn openat(d: &File, n: &str, flags: i32, mode: u32) -> Result<File> {
    ensure!(
        !n.contains('/') && n != "." && n != "..",
        "legacy_bad_component"
    );
    let n = CString::new(n)?;
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            n.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn parent(base: &Path, rel: &str) -> Result<(File, String)> {
    let p = base.join(rel);
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("legacy_bad_path"))?
        .to_owned();
    Ok((directory(p.parent().unwrap())?, name))
}
fn read(base: &Path, rel: &str, max: u64) -> Result<(FileState, Vec<u8>)> {
    let (d, n) = parent(base, rel)?;
    let f = openat(&d, &n, libc::O_RDONLY, 0)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= max,
        "legacy_unsafe_file"
    );
    let mut b = Vec::new();
    (&f).take(max + 1).read_to_end(&mut b)?;
    let after = f.metadata()?;
    let named = openat(&d, &n, libc::O_RDONLY, 0)?.metadata()?;
    ensure!(
        b.len() as u64 == m.len()
            && state(&m, &b) == state(&after, &b)
            && state(&m, &b) == state(&named, &b),
        "legacy_source_changed"
    );
    Ok((state(&m, &b), b))
}
fn absent(base: &Path, rel: &str) -> Result<()> {
    let rel = vendor_relative(base, rel)?;
    let mut d = directory(base)?;
    let components: Vec<_> = Path::new(&rel).components().collect();
    for (i, c) in components.iter().enumerate() {
        let Component::Normal(n) = c else {
            bail!("legacy_bad_path")
        };
        let n = n
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("legacy_non_utf8"))?;
        match openat(&d, n, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(next) => {
                check_dir(&next)?;
                ensure!(i + 1 != components.len(), "legacy_unexpected_existing_path");
                d = next;
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(());
            }
            Err(_) => bail!("legacy_unexpected_existing_or_unsafe_path"),
        }
    }
    bail!("legacy_unexpected_existing_path")
}
// Explicit merged-/usr compatibility only. Other link ancestors fail closed.
fn vendor_relative(base: &Path, rel: &str) -> Result<String> {
    if let Some(rest) = rel.strip_prefix("lib/") {
        let p = base.join("lib");
        if let Ok(m) = p.symlink_metadata()
            && m.file_type().is_symlink()
        {
            let t = std::fs::read_link(&p)?;
            ensure!(
                m.uid() == 0 && (t == Path::new("usr/lib") || t == Path::new("/usr/lib")),
                "legacy_unknown_vendor_link"
            );
            return Ok(format!("usr/lib/{rest}"));
        }
    }
    Ok(rel.to_owned())
}
fn link(base: &Path) -> Result<String> {
    let (d, n) = parent(base, ENTRY)?;
    let name = CString::new(n)?;
    let mut b = [0u8; 4096];
    let len =
        unsafe { libc::readlinkat(d.as_raw_fd(), name.as_ptr(), b.as_mut_ptr().cast(), b.len()) };
    ensure!(
        len > 0 && (len as usize) < b.len(),
        "legacy_entry_link_required"
    );
    let target = String::from_utf8(b[..len as usize].to_vec())?;
    ensure!(target == format!("/{OLD}"), "legacy_unknown_entry_target");
    let m = base.join(ENTRY).symlink_metadata()?;
    ensure!(
        m.file_type().is_symlink() && m.uid() == 0,
        "legacy_unsafe_entry"
    );
    Ok(target)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub fixture_root: Option<PathBuf>,
    pub files: BTreeMap<String, FileState>,
    pub entry_target: String,
    pub entry_identity: FileState,
    pub ancillary_links: BTreeMap<String, (String, FileState)>,
    pub json_fields: BTreeMap<String, Vec<String>>,
    pub units: BTreeMap<String, String>,
    pub states: BTreeMap<String, String>,
    pub plan_sha256: String,
}
fn seal(p: &Plan) -> Result<String> {
    let mut p = p.clone();
    p.plan_sha256.clear();
    Ok(hash(&serde_json::to_vec(&p)?))
}
fn unit(base: &Path, name: &str, fixture: bool) -> Result<(FileState, String)> {
    let (s, b) = read(base, &format!("etc/systemd/system/{name}"), 65536)?;
    if !fixture {
        let expected = if name == UNITS[0] {
            "a999ffd4ce9c74fe068a867900d489d782205ee93743fa5842f971dab41ac834"
        } else {
            "7ca50a5f2e06a077e772e5a1298e99fc3b1417f7cce0317de3ecd198dc3bef4b"
        };
        ensure!(s.sha256 == expected, "legacy_unknown_unit_lineage");
    }
    let text = String::from_utf8(b)?;
    let commands: Vec<_> = text
        .lines()
        .filter_map(|l| l.strip_prefix("ExecStart="))
        .collect();
    ensure!(commands.len() == 1, "legacy_unknown_unit_argv");
    let sub = if name == UNITS[0] { "core" } else { "apps" };
    let allowed: Vec<_> = ["/srv/kagnode", "/srv/kagnode/core"]
        .into_iter()
        .flat_map(|r| {
            [
                format!("/usr/bin/kagnode {sub} --root {r} serve"),
                format!("/usr/bin/kagnode {sub} serve --root {r}"),
            ]
        })
        .collect();
    ensure!(
        allowed.contains(&commands[0].to_string()),
        "legacy_unknown_unit_argv"
    );
    // No override layer is silently ignored, including vendor/runtime drop-ins.
    for dir in [
        "etc/systemd/system",
        "run/systemd/system",
        "usr/lib/systemd/system",
        "lib/systemd/system",
    ] {
        for override_name in override_names(name) {
            absent(base, &format!("{dir}/{override_name}"))?;
        }
        if dir != "etc/systemd/system" {
            absent(base, &format!("{dir}/{name}"))?;
        }
    }
    Ok((s, commands[0].to_owned()))
}
fn override_names(name: &str) -> Vec<String> {
    let (stem, kind) = name.rsplit_once('.').expect("fixed unit kind");
    let mut names = vec![format!("{name}.d"), format!("{kind}.d")];
    for (i, c) in stem.char_indices() {
        if c == '-' {
            names.push(format!("{}.{}.d", &stem[..=i], kind));
        }
    }
    names.sort();
    names.dedup();
    names
}
fn terminate(c: &mut std::process::Child) {
    unsafe { libc::kill(-(c.id() as i32), libc::SIGKILL) };
    let _ = c.wait();
}
fn show() -> Result<BTreeMap<String, String>> {
    let mut command = Command::new("/usr/bin/systemctl");
    command.args(["show","--no-pager","--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,MainPID,ExecStart,NeedDaemonReload,User"])
        .args(UNITS).args(NEW_UNITS).env_clear().env("LC_ALL","C").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).process_group(0);
    // Seal all inherited descriptors at exec, retaining stdio. Linux-only backend.
    unsafe {
        command.pre_exec(|| {
            if libc::close_range(3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC as i32) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut c = command.spawn()?;
    let mut out = c.stdout.take().unwrap();
    let fd = out.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let e = std::io::Error::last_os_error();
        terminate(&mut c);
        return Err(e.into());
    }
    let start = Instant::now();
    let mut b = Vec::new();
    let status = loop {
        let mut part = [0u8; 4096];
        match out.read(&mut part) {
            Ok(n) => b.extend_from_slice(&part[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => {
                terminate(&mut c);
                return Err(e.into());
            }
        };
        if b.len() > 32768 || start.elapsed() > Duration::from_secs(5) {
            terminate(&mut c);
            bail!("legacy_probe_bound")
        }
        let status = match c.try_wait() {
            Ok(s) => s,
            Err(e) => {
                terminate(&mut c);
                return Err(e.into());
            }
        };
        if let Some(s) = status {
            let remaining = 32769 - b.len();
            let drained = (&mut out).take(remaining as u64).read_to_end(&mut b);
            // A descendant holding the pipe cannot extend the probe lifetime.
            unsafe { libc::kill(-(c.id() as i32), libc::SIGKILL) };
            drained?;
            break s;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    ensure!(
        status.success() && status.signal().is_none() && b.len() <= 32768,
        "legacy_probe_failed"
    );
    parse_show(&String::from_utf8(b)?)
}
fn parse_show(text: &str) -> Result<BTreeMap<String, String>> {
    ensure!(text.len() <= 32768, "legacy_probe_bound");
    let mut states = BTreeMap::new();
    for block in text.trim().split("\n\n") {
        let fields: BTreeMap<_, _> = block.lines().filter_map(|l| l.split_once('=')).collect();
        let id = *fields
            .get("Id")
            .ok_or_else(|| anyhow::anyhow!("legacy_probe_id"))?;
        ensure!(
            UNITS.contains(&id) || NEW_UNITS.contains(&id),
            "legacy_probe_unknown_unit"
        );
        ensure!(
            fields.get("DropInPaths") == Some(&""),
            "legacy_dropins_present"
        );
        if UNITS.contains(&id) {
            ensure!(
                fields.get("NeedDaemonReload") == Some(&"no")
                    && matches!(fields.get("User"), Some(&"") | Some(&"root"))
                    && fields.get("LoadState") == Some(&"loaded")
                    && fields.get("ActiveState") == Some(&"active")
                    && fields.get("SubState") == Some(&"running")
                    && fields
                        .get("MainPID")
                        .and_then(|p| p.parse::<u32>().ok())
                        .is_some_and(|p| p > 0)
                    && fields.get("FragmentPath")
                        == Some(&format!("/etc/systemd/system/{id}").as_str()),
                "legacy_unit_state_unrecognized"
            );
        } else {
            ensure!(
                fields.get("LoadState") == Some(&"not-found")
                    && fields.get("ActiveState") == Some(&"inactive"),
                "legacy_rust_unit_present"
            );
        }
        ensure!(
            states.insert(id.to_owned(), block.to_owned()).is_none(),
            "legacy_duplicate_unit"
        );
    }
    ensure!(
        states.len() == UNITS.len() + NEW_UNITS.len(),
        "legacy_incomplete_unit_state"
    );
    Ok(states)
}
fn inspect_at(base: &Path, fixture: bool) -> Result<Plan> {
    root()?;
    let bd = directory(base)?;
    if fixture {
        ensure!(
            bd.metadata()?.mode() & 0o777 == 0o700,
            "legacy_fixture_private_required"
        );
    }
    let mut p = Plan {
        schema: 1,
        fixture_root: fixture.then(|| base.to_path_buf()),
        files: BTreeMap::new(),
        ancillary_links: BTreeMap::new(),
        entry_target: link(base)?,
        entry_identity: state(
            &base.join(ENTRY).symlink_metadata()?,
            link(base)?.as_bytes(),
        ),
        json_fields: BTreeMap::new(),
        units: BTreeMap::new(),
        states: BTreeMap::new(),
        plan_sha256: String::new(),
    };
    let (s, b) = read(base, OLD, MAX)?;
    ensure!(
        s.mode & 0o111 != 0
            && s.sha256
                == if fixture {
                    hash(FIXTURE)
                } else {
                    KNOWN.to_owned()
                },
        "legacy_unknown_binary_lineage"
    );
    p.files.insert(OLD.into(), s);
    drop(b);
    for rel in DATA {
        let (s, b) = read(base, rel, 1048576)?;
        let v: serde_json::Value = serde_json::from_slice(&b)?;
        let o = v
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("legacy_json_object_required"))?;
        let allowed: Vec<&str> = if rel == DATA[0] {
            vec!["panels"]
        } else {
            vec![
                "active",
                "adapter",
                "channel",
                "installed_at",
                "source_commit",
                "version",
            ]
        };
        ensure!(
            o.keys().all(|k| allowed.contains(&k.as_str())),
            "legacy_unknown_json_structure"
        );
        ensure!(!o.is_empty(), "legacy_empty_data_requires_review");
        p.json_fields
            .insert(rel.into(), o.keys().cloned().collect());
        p.files.insert(rel.into(), s);
    }
    if base
        .join("lib")
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        vendor_relative(base, "lib/systemd/system")?;
        let m = base.join("lib").symlink_metadata()?;
        let target = std::fs::read_link(base.join("lib"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("legacy_vendor_link_utf8"))?
            .to_owned();
        p.ancillary_links
            .insert("lib".into(), (target.clone(), state(&m, target.as_bytes())));
    }
    for name in UNITS {
        for dir in [
            "etc/systemd/system",
            "run/systemd/system",
            "usr/lib/systemd/system",
            "lib/systemd/system",
        ] {
            for target in ["multi-user.target.wants", "timers.target.wants"] {
                let rel = vendor_relative(base, &format!("{dir}/{target}/{name}"))?;
                if let Ok(m) = base.join(&rel).symlink_metadata() {
                    let (d, n) = parent(base, &rel)?;
                    let n = CString::new(n)?;
                    let mut b = [0u8; 4096];
                    let count = unsafe {
                        libc::readlinkat(d.as_raw_fd(), n.as_ptr(), b.as_mut_ptr().cast(), b.len())
                    };
                    ensure!(
                        count > 0
                            && (count as usize) < b.len()
                            && m.file_type().is_symlink()
                            && m.uid() == 0,
                        "legacy_unsafe_enable_link"
                    );
                    let t = String::from_utf8(b[..count as usize].to_vec())?;
                    ensure!(
                        t == format!("../{name}") || t == format!("/etc/systemd/system/{name}"),
                        "legacy_unknown_enable_link"
                    );
                    p.ancillary_links
                        .insert(rel, (t.clone(), state(&m, t.as_bytes())));
                } else {
                    absent(base, &rel)?;
                }
            }
        }
        let (s, argv) = unit(base, name, fixture)?;
        p.files.insert(format!("etc/systemd/system/{name}"), s);
        p.units.insert(name.into(), argv);
    }
    for name in NEW_UNITS {
        for dir in [
            "etc/systemd/system",
            "run/systemd/system",
            "usr/lib/systemd/system",
            "lib/systemd/system",
        ] {
            absent(base, &format!("{dir}/{name}"))?;
            for target in ["multi-user.target.wants", "timers.target.wants"] {
                absent(base, &format!("{dir}/{target}/{name}"))?;
            }
            for override_name in override_names(name) {
                absent(base, &format!("{dir}/{override_name}"))?;
            }
        }
    }
    for rel in [
        "srv/kagnode/daemon",
        "var/lib/kagnode-daemon",
        "etc/kagnode/daemon",
        "usr/libexec/kagnode-daemon",
        "run/kagnode-daemon",
        "srv/kagnode/daemon/state/daemon.sqlite",
        "srv/kagnode/daemon/controller/daemon.sqlite",
        "srv/kagnode/daemon/daemon.sqlite",
        "srv/kagnode/controller/daemon.sqlite",
    ] {
        absent(base, rel)?;
    }
    if fixture {
        p.states.insert(
            "fixture".into(),
            "synthetic; no service execution or privilege import".into(),
        );
    } else {
        p.files.insert(
            "usr/bin/systemctl".into(),
            read(base, "usr/bin/systemctl", MAX)?.0,
        );
        let shown = show()?;
        for (unit, argv) in &p.units {
            let block = &shown[unit];
            ensure!(
                block.contains(&format!("argv[]={argv} ;")),
                "legacy_effective_argv_mismatch"
            );
        }
        p.states = shown;
    }
    for (rel, expected) in &p.files {
        ensure!(
            &read(base, rel, MAX)?.0 == expected,
            "legacy_source_changed"
        );
    }
    ensure!(
        link(base)? == p.entry_target
            && state(
                &base.join(ENTRY).symlink_metadata()?,
                p.entry_target.as_bytes()
            ) == p.entry_identity,
        "legacy_entry_changed"
    );
    for (rel, (target, expected)) in &p.ancillary_links {
        let actual = std::fs::read_link(base.join(rel))?;
        ensure!(
            actual == Path::new(target)
                && state(&base.join(rel).symlink_metadata()?, target.as_bytes()) == *expected,
            "legacy_link_changed"
        );
    }
    p.plan_sha256 = seal(&p)?;
    Ok(p)
}
/// Fixed host inventory. This never copies or changes live files.
pub fn inspect() -> Result<Plan> {
    inspect_at(Path::new("/"), false)
}
/// Explicit synthetic fixture only: fixed marker bytes distinguish it from host data.
pub fn inspect_fixture(base: &Path) -> Result<Plan> {
    ensure!(base != Path::new("/"), "legacy_fixture_root_required");
    inspect_at(base, true)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub plan_sha256: String,
    pub phase: String,
    pub source: BTreeMap<String, FileState>,
    pub copied: BTreeMap<String, FileState>,
}
fn create(d: &File, name: &str, b: &[u8], mode: u32) -> Result<()> {
    let mut f = openat(d, name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode)?;
    f.write_all(b)?;
    ensure!(
        unsafe { libc::fchmod(f.as_raw_fd(), mode) } == 0,
        "legacy_copy_mode_failed"
    );
    f.sync_all()?;
    d.sync_all()?;
    Ok(())
}
fn revalidate(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == 1 && p.plan_sha256 == seal(p)?,
        "legacy_plan_digest_mismatch"
    );
    let now = match &p.fixture_root {
        Some(b) => inspect_fixture(b)?,
        None => inspect()?,
    };
    ensure!(&now == p, "legacy_observed_state_changed");
    Ok(())
}
/// COPY only, into a new private sibling directory of the synthetic fixture.
/// Existing incomplete directories are deliberately never resumed or cleaned.
pub fn copy_dry_run(p: &Plan, destination: &Path) -> Result<Receipt> {
    copy_with(p, destination, |_| Ok(()))
}
fn copy_with(
    p: &Plan,
    destination: &Path,
    after_copy: impl Fn(usize) -> Result<()>,
) -> Result<Receipt> {
    root()?;
    let base = p
        .fixture_root
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("legacy_host_copy_unavailable"))?;
    ensure!(
        destination.parent() == base.parent() && destination != base,
        "legacy_destination_separation_required"
    );
    revalidate(p)?;
    let parent = directory(
        destination
            .parent()
            .ok_or_else(|| anyhow::anyhow!("legacy_destination_parent"))?,
    )?;
    let name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("legacy_destination_name"))?;
    if destination.symlink_metadata().is_ok() {
        let d = directory(destination)?;
        ensure!(
            d.metadata()?.mode() & 0o777 == 0o700,
            "legacy_receipt_private_required"
        );
        let (_, b) = read(destination, "receipt.json", 1048576)?;
        let r: Receipt = serde_json::from_slice(&b)?;
        ensure!(
            r.phase == "complete" && r.plan_sha256 == p.plan_sha256 && r.source == p.files,
            "legacy_partial_or_replay_mismatch"
        );
        for (i, source) in p.files.values().enumerate() {
            let name = format!("copy-{i:02}");
            let s = r
                .copied
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("legacy_receipt_missing_copy"))?;
            ensure!(
                &read(destination, &name, MAX)?.0 == s
                    && s.sha256 == source.sha256
                    && s.mode == source.mode
                    && s.uid == source.uid
                    && s.gid == source.gid,
                "legacy_copy_changed"
            );
        }
        ensure!(r.copied.len() == p.files.len(), "legacy_incomplete_receipt");
        return Ok(r);
    }
    let n = CString::new(name)?;
    ensure!(
        unsafe { libc::mkdirat(parent.as_raw_fd(), n.as_ptr(), 0o700) } == 0,
        "legacy_destination_create_failed"
    );
    parent.sync_all()?;
    let d = directory(destination)?;
    let mut r = Receipt {
        plan_sha256: p.plan_sha256.clone(),
        phase: "pending".into(),
        source: p.files.clone(),
        copied: BTreeMap::new(),
    };
    create(&d, "intent.json", &serde_json::to_vec(&r)?, 0o600)?;
    for (i, (rel, expected)) in p.files.iter().enumerate() {
        let (s, b) = read(base, rel, MAX)?;
        ensure!(&s == expected, "legacy_source_changed");
        let name = format!("copy-{i:02}");
        create(&d, &name, &b, expected.mode & 0o777)?;
        let (copied, bytes) = read(destination, &name, MAX)?;
        ensure!(
            copied.sha256 == s.sha256
                && bytes == b
                && copied.mode & 0o777 == s.mode & 0o777
                && copied.uid == s.uid
                && copied.gid == s.gid,
            "legacy_copy_mismatch"
        );
        r.copied.insert(name, copied);
        after_copy(i)?;
    }
    revalidate(p)?;
    r.phase = "complete".into();
    create(&d, "receipt.json", &serde_json::to_vec(&r)?, 0o600)?;
    Ok(r)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub observed_plan_sha256: String,
    pub retained_binary: String,
    pub retained_binary_sha256: String,
    pub pin_argv: BTreeMap<String, String>,
    pub preserved_files: BTreeMap<String, FileState>,
    pub preserved_links: BTreeMap<String, (String, FileState)>,
    pub entry_identity: FileState,
    pub entry_target: String,
    pub activation_available: bool,
}
/// A typed future restoration contract, never an executable rollback operation.
pub fn rollback_plan(p: &Plan) -> Result<RollbackPlan> {
    revalidate(p)?;
    Ok(RollbackPlan {
        observed_plan_sha256: p.plan_sha256.clone(),
        retained_binary: format!("/{OLD}"),
        retained_binary_sha256: p.files[OLD].sha256.clone(),
        pin_argv: p
            .units
            .iter()
            .map(|(n, a)| {
                (
                    n.clone(),
                    a.replacen("/usr/bin/kagnode", &format!("/{OLD}"), 1),
                )
            })
            .collect(),
        preserved_files: p.files.clone(),
        preserved_links: p.ancillary_links.clone(),
        entry_identity: p.entry_identity.clone(),
        entry_target: p.entry_target.clone(),
        activation_available: false,
    })
}
/// No boolean backup attestation can unlock mutable adoption in this draft.
pub fn apply_unavailable() -> Result<()> {
    bail!(
        "legacy_apply_unavailable: independent review, verified consistent encrypted recovery, native unit pinning and full adoption/rollback qualification required"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    fn fixture() -> Option<(tempfile::TempDir, PathBuf)> {
        if unsafe { libc::geteuid() } != 0 {
            return None;
        }
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let b = temp.path().join("source");
        fs::create_dir(&b).unwrap();
        fs::set_permissions(&b, fs::Permissions::from_mode(0o700)).unwrap();
        for rel in [
            OLD,
            ENTRY,
            DATA[0],
            DATA[1],
            "etc/systemd/system/kagnode-core.service",
        ] {
            fs::create_dir_all(b.join(rel).parent().unwrap()).unwrap();
        }
        fs::write(b.join(OLD), FIXTURE).unwrap();
        fs::set_permissions(b.join(OLD), fs::Permissions::from_mode(0o755)).unwrap();
        symlink(format!("/{OLD}"), b.join(ENTRY)).unwrap();
        fs::write(
            b.join(DATA[0]),
            br#"{"panels":{"private":"SYNTHETIC-SECRET"}}"#,
        )
        .unwrap();
        fs::write(b.join(DATA[1]), br#"{"active":true,"version":"synthetic"}"#).unwrap();
        for (n, s) in [(UNITS[0], "core"), (UNITS[1], "apps")] {
            fs::write(b.join(format!("etc/systemd/system/{n}")),format!("[Service]\nUser=root\nExecStart=/usr/bin/kagnode {s} --root /srv/kagnode serve\n")).unwrap();
        }
        Some((temp, b))
    }
    #[test]
    fn copy_replay_preserves_exact_source_and_private_receipt() {
        let Some((t, b)) = fixture() else { return };
        let p = inspect_fixture(&b).unwrap();
        let d = t.path().join("copy");
        let r = copy_dry_run(&p, &d).unwrap();
        assert_eq!(r, copy_dry_run(&p, &d).unwrap());
        assert_eq!(p, inspect_fixture(&b).unwrap());
        assert_eq!(
            fs::metadata(d.join("receipt.json")).unwrap().mode() & 0o777,
            0o600
        );
        let exposed = serde_json::to_string(&p).unwrap() + &serde_json::to_string(&r).unwrap();
        assert!(!exposed.contains("SYNTHETIC-SECRET"));
        assert!(!exposed.contains("Operator"));
    }
    #[test]
    fn unknown_binary_refused() {
        let Some((_t, b)) = fixture() else { return };
        fs::write(b.join(OLD), b"unknown").unwrap();
        assert!(inspect_fixture(&b).is_err());
    }
    #[test]
    fn malformed_or_unknown_json_refused() {
        let Some((_t, b)) = fixture() else { return };
        for bytes in [b"[]".as_slice(), b"{", br#"{"oauth_operator":true}"#] {
            fs::write(b.join(DATA[0]), bytes).unwrap();
            assert!(inspect_fixture(&b).is_err());
        }
    }
    #[test]
    fn unknown_unit_arguments_refused() {
        let Some((_t, b)) = fixture() else { return };
        for cmd in [
            "/bin/sh -c bad",
            "/usr/bin/kagnode apps --root /tmp serve",
            "/usr/bin/kagnode core serve --root /srv/kagnode extra",
        ] {
            fs::write(
                b.join("etc/systemd/system/kagnode-core.service"),
                format!("ExecStart={cmd}\n"),
            )
            .unwrap();
            assert!(inspect_fixture(&b).is_err());
        }
    }
    #[test]
    fn fixed_core_root_order_retained_in_rollback() {
        let Some((_t, b)) = fixture() else { return };
        fs::write(
            b.join("etc/systemd/system/kagnode-core.service"),
            "ExecStart=/usr/bin/kagnode core serve --root /srv/kagnode/core\n",
        )
        .unwrap();
        let p = inspect_fixture(&b).unwrap();
        let r = rollback_plan(&p).unwrap();
        assert!(r.pin_argv[UNITS[0]].ends_with("core serve --root /srv/kagnode/core"));
        assert!(!r.activation_available);
        assert!(apply_unavailable().is_err());
    }
    #[test]
    fn symlink_and_hardlink_data_refused() {
        let Some((_t, b)) = fixture() else { return };
        let path = b.join(DATA[0]);
        fs::rename(&path, b.join("saved")).unwrap();
        symlink(b.join("saved"), &path).unwrap();
        assert!(inspect_fixture(&b).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(b.join("saved"), &path).unwrap();
        assert!(inspect_fixture(&b).is_err());
    }
    #[test]
    fn unsafe_directory_and_destination_separation_refused() {
        let Some((t, b)) = fixture() else { return };
        let p = inspect_fixture(&b).unwrap();
        assert!(copy_dry_run(&p, &b.join("copy")).is_err());
        assert!(copy_dry_run(&p, &b).is_err());
        fs::set_permissions(b.join("srv"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(inspect_fixture(&b).is_err());
        assert!(!t.path().join("copy").exists());
    }
    #[test]
    fn source_change_and_plan_tampering_refused() {
        let Some((t, b)) = fixture() else { return };
        let mut p = inspect_fixture(&b).unwrap();
        p.entry_target = "/bad".into();
        assert!(rollback_plan(&p).is_err());
        assert!(copy_dry_run(&p, &t.path().join("copy")).is_err());
        let p = inspect_fixture(&b).unwrap();
        fs::write(b.join(DATA[1]), br#"{"active":false}"#).unwrap();
        assert!(rollback_plan(&p).is_err());
        assert!(copy_dry_run(&p, &t.path().join("copy")).is_err());
    }
    #[test]
    fn partial_copy_never_retried_and_race_leaves_intent() {
        let Some((t, b)) = fixture() else { return };
        let p = inspect_fixture(&b).unwrap();
        let d = t.path().join("copy");
        let result = copy_with(&p, &d, |i| {
            if i == 0 {
                fs::write(b.join(DATA[0]), br#"{"panels":[]}"#)?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(d.join("intent.json").exists());
        assert!(!d.join("receipt.json").exists());
        assert!(copy_dry_run(&inspect_fixture(&b).unwrap(), &d).is_err());
    }
    #[test]
    fn changed_destination_refuses_replay() {
        let Some((t, b)) = fixture() else { return };
        let p = inspect_fixture(&b).unwrap();
        let d = t.path().join("copy");
        copy_dry_run(&p, &d).unwrap();
        fs::write(d.join("copy-00"), b"changed").unwrap();
        assert!(copy_dry_run(&p, &d).is_err());
    }
    #[test]
    fn dropin_and_rust_store_refused() {
        let Some((_t, b)) = fixture() else { return };
        let dropin = b.join("etc/systemd/system/kagnode-core.service.d");
        fs::create_dir(&dropin).unwrap();
        assert!(inspect_fixture(&b).is_err());
        fs::remove_dir(&dropin).unwrap();
        let db = b.join("srv/kagnode/controller/daemon.sqlite");
        fs::create_dir_all(db.parent().unwrap()).unwrap();
        fs::write(db, b"never opened").unwrap();
        assert!(inspect_fixture(&b).is_err());
    }
    #[test]
    fn global_and_dash_dropins_refused() {
        let Some((_t, b)) = fixture() else { return };
        for name in [
            "service.d",
            "kagnode-.service.d",
            "kagnode-daemon-.service.d",
            "timer.d",
        ] {
            let p = b.join("etc/systemd/system").join(name);
            fs::create_dir(&p).unwrap();
            assert!(inspect_fixture(&b).is_err(), "{name}");
            fs::remove_dir(p).unwrap();
        }
    }
    #[test]
    fn actual_native_broker_and_partial_install_refused() {
        let Some((_t, b)) = fixture() else { return };
        for rel in [
            "etc/systemd/system/kagnode-daemon-broker.service",
            "etc/kagnode/daemon/config",
            "srv/kagnode/daemon/partial",
            "var/lib/kagnode-daemon/partial",
            "usr/libexec/kagnode-daemon/partial",
            "run/kagnode-daemon/partial",
        ] {
            let p = b.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"partial").unwrap();
            assert!(inspect_fixture(&b).is_err(), "{rel}");
            fs::remove_file(&p).unwrap();
            if rel != "etc/systemd/system/kagnode-daemon-broker.service" {
                fs::remove_dir(p.parent().unwrap()).unwrap();
            }
        }
    }
    #[test]
    fn enable_link_metadata_bound_and_unknown_target_refused() {
        let Some((_t, b)) = fixture() else { return };
        let wants = b.join("etc/systemd/system/multi-user.target.wants");
        fs::create_dir(&wants).unwrap();
        let path = wants.join(UNITS[0]);
        symlink("../kagnode-core.service", &path).unwrap();
        let p = inspect_fixture(&b).unwrap();
        assert_eq!(p.ancillary_links.len(), 1);
        fs::remove_file(&path).unwrap();
        symlink("/unknown", &path).unwrap();
        assert!(inspect_fixture(&b).is_err());
        assert!(rollback_plan(&p).is_err());
    }
    fn show_fixture() -> String {
        UNITS.iter().map(|n|format!("Id={n}\nDropInPaths=\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=5\nNeedDaemonReload=no\nUser=root\nFragmentPath=/etc/systemd/system/{n}")).chain(NEW_UNITS.iter().map(|n|format!("Id={n}\nDropInPaths=\nLoadState=not-found\nActiveState=inactive"))).collect::<Vec<_>>().join("\n\n")
    }
    #[test]
    fn old_unit_state_requires_complete_unchanged_running_root() {
        let good = show_fixture();
        assert!(parse_show(&good).is_ok());
        for (old, new) in [
            ("ActiveState=active", "ActiveState=failed"),
            ("NeedDaemonReload=no", "NeedDaemonReload=yes"),
            ("User=root", "User=other"),
            ("MainPID=5", "MainPID=0"),
            ("DropInPaths=\n", "DropInPaths=/unknown\n"),
            ("LoadState=not-found", "LoadState=loaded"),
        ] {
            assert!(parse_show(&good.replacen(old, new, 1)).is_err(), "{old}");
        }
        assert!(parse_show(&good.split("\n\n").skip(1).collect::<Vec<_>>().join("\n\n")).is_err());
    }
    #[test]
    fn fixture_never_accepts_host_or_owner_assertion() {
        assert!(inspect_fixture(Path::new("/")).is_err());
        let Some((_t, b)) = fixture() else { return };
        let p = inspect_fixture(&b).unwrap();
        let v = serde_json::to_value(p).unwrap();
        assert!(v.get("owner_uid").is_none());
        assert!(v.get("roles").is_none());
        assert!(v.get("backup_verified").is_none());
    }
}
