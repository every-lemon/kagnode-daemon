use crate::store::Profile;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn unit(profile: Profile, broker: bool, origin: &str) -> String {
    let mut s = if broker {
        "[Unit]\nDescription=KagNode restricted native service broker\nAfter=network.target\n[Service]\nType=simple\nUser=root\nExecStart=/usr/libexec/kagnode-daemon/kagnode broker --allowed-uid=@UID@\nRuntimeDirectory=kagnode-daemon\nRuntimeDirectoryMode=0755\nReadWritePaths=/run/kagnode-daemon /var/lib/kagnode-daemon /etc/kagnode/daemon\n".to_owned()
    } else {
        format!(
            "[Unit]\nDescription=KagNode Daemon\nAfter=network.target kagnode-daemon-broker.service\nRequires=kagnode-daemon-broker.service\n[Service]\nType=simple\nUser=kn-daemon\nGroup=kn-daemon\nExecStart=/usr/libexec/kagnode-daemon/kagnode --root /srv/kagnode/daemon/controller serve --origin {origin}\nReadWritePaths=/srv/kagnode/daemon/controller\n"
        )
    };
    s += "Restart=on-failure\nRestartSec=5\nUMask=0077\nPrivateTmp=true\nProtectHome=true\nNoNewPrivileges=true\n";
    if profile == Profile::Production {
        s += "ProtectSystem=strict\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nProtectKernelLogs=true\nRestrictSUIDSGID=true\nLockPersonality=true\nMemoryHigh=192M\nMemoryMax=256M\nTasksMax=64\nLogRateLimitIntervalSec=30s\nLogRateLimitBurst=200\n";
    }
    s += "[Install]\nWantedBy=multi-user.target\n";
    s
}
pub fn units(profile: Profile, origin: &str) -> BTreeMap<String, String> {
    let mut files = BTreeMap::from([
        (
            "kagnode-daemon.service".into(),
            unit(profile, false, origin),
        ),
        (
            "kagnode-daemon-broker.service".into(),
            unit(profile, true, origin),
        ),
    ]);
    if profile == Profile::Production {
        files.insert("kagnode-daemon-monitor.service".into(),"[Unit]\nDescription=KagNode Daemon local health inspection\nAfter=kagnode-daemon.service\n[Service]\nType=oneshot\nUser=kn-daemon\nExecStart=/usr/libexec/kagnode-daemon/kagnode health\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nReadWritePaths=/srv/kagnode/daemon/controller\n".into());
        files.insert("kagnode-daemon-monitor.timer".into(),"[Unit]\nDescription=Check KagNode Daemon health\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\nRandomizedDelaySec=10\n[Install]\nWantedBy=timers.target\n".into());
        files.insert("kagnode-daemon-backup.service".into(),"[Unit]\nDescription=Encrypted KagNode Daemon control database snapshot\nConditionPathExists=/etc/kagnode/daemon/backup-destination\n[Service]\nType=oneshot\nUser=root\nExecStart=/usr/libexec/kagnode-daemon/kagnode backup scheduled\nUMask=0077\nNoNewPrivileges=true\nProtectHome=true\nPrivateTmp=true\n".into());
        files.insert("kagnode-daemon-backup.timer".into(),"[Unit]\nDescription=Schedule KagNode Daemon backups after destination configuration\n[Timer]\nOnCalendar=*-*-* 03:30:00 UTC\nRandomizedDelaySec=15min\nPersistent=true\n[Install]\nWantedBy=timers.target\n".into());
    }
    files
}
pub fn plan(profile: Profile, web: bool, origin: &str) -> Result<Value> {
    ensure!(
        origin == "http://127.0.0.1:8750" || origin.starts_with("https://"),
        "Use a local or HTTPS dashboard origin"
    );
    let url = reqwest::Url::parse(origin)?;
    ensure!(
        url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && !origin.chars().any(char::is_whitespace),
        "Configure an origin without paths, credentials or whitespace"
    );
    let canonical = url.origin().ascii_serialization();
    ensure!(
        (origin == canonical || origin == format!("{canonical}/"))
            && origin
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":/.-_[]".contains(&b)),
        "Use a canonical local or HTTPS origin without systemd quoting, escapes or substitutions"
    );
    Ok(
        json!({"schema":1,"product":"kagnode-daemon","version":env!("CARGO_PKG_VERSION"),"profile":profile,"web":web,"origin":origin,"root":"/srv/kagnode/daemon","service_user":"kn-daemon","units":units(profile,origin).keys().collect::<Vec<_>>(),"unit_definitions":units(profile,origin),"production_backup":"scheduled only after a private destination is configured","existing_applications":"retained","existing_cli_migration":"blocked until compatibility is qualified","network_or_ha_activation":false}),
    )
}
fn new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    ensure!(
        !path.exists() && !path.is_symlink(),
        "An installation target already exists: {}",
        path.display()
    );
    std::fs::create_dir_all(path.parent().unwrap())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
/// Compatibility entry point. New callers should retain an explicit reviewed plan/hash.
pub fn apply(
    email: &str,
    password: &str,
    profile: Profile,
    web: bool,
    origin: &str,
) -> Result<Value> {
    let options = crate::native_install::Options {
        profile,
        web,
        origin: origin.into(),
    };
    let choice = crate::native_install::ProtectionChoice::Protected {
        account: email.into(),
    };
    let plan = crate::native_install::plan(options, choice)?;
    crate::native_install::apply_reviewed(
        &plan,
        crate::native_install::Protection::Protected {
            account: email,
            password,
        },
        &plan.plan_sha256,
    )
}
pub fn configure_backup(destination: &Path) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Root must configure the private backup destination"
    );
    ensure!(
        destination.is_absolute()
            && !destination
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
            && !destination.starts_with("/etc/kagnode")
            && !destination.starts_with("/var/lib/kagnode-keys"),
        "Choose a backup directory separate from recovery keys and configuration"
    );
    for p in destination.ancestors().filter(|p| p.exists()) {
        ensure!(!p.is_symlink(), "Backup paths cannot traverse symlinks");
    }
    std::fs::create_dir_all(destination)?;
    let m = destination.metadata()?;
    ensure!(m.uid() == 0, "Backup destination must belong to root");
    ensure!(
        m.mode() & 0o077 == 0 || std::fs::read_dir(destination)?.next().is_none(),
        "Choose a private backup directory; existing shared directory permissions are retained"
    );
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))?;
    let path = PathBuf::from("/etc/kagnode/daemon/backup-destination");
    new_file(&path, destination.to_string_lossy().as_bytes(), 0o600)?;
    Ok(
        json!({"destination":destination,"scheduled_when_production_timer_enabled":true,"off_host_copy_configured":false}),
    )
}
