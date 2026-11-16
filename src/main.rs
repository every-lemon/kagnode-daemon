use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use kagnode_daemon::{
    catalog,
    store::{Profile, Store},
    web::{self, App},
};
use serde_json::json;
use std::{
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
};
#[derive(Parser)]
#[command(
    name = "kagnode",
    version,
    about = "KagNode. Daemon — manage your open-source workspace"
)]
struct Args {
    #[arg(
        long,
        global = true,
        default_value = "/srv/kagnode/daemon/controller",
        env = "KAGNODE_DAEMON_ROOT"
    )]
    root: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Explicit single-owner setup; never downgrades an existing protected store.
    InitOwner {
        #[arg(long, value_enum, default_value = "light")]
        profile: Profile,
    },
    /// Backend automation endpoint. Reads a bounded v1 request from stdin;
    /// credentials must never be supplied in command arguments.
    User {
        #[arg(value_parser=["login","owner-session","whoami","capabilities","logout","reauthenticate","list","create","update","reset-password","change-password","enable-protection","security-get","security-set","root-recover","request"])]
        action: String,
    },
    Init {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_file: PathBuf,
        #[arg(long, value_enum, default_value = "light")]
        profile: Profile,
        #[arg(long)]
        web: bool,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1:8750")]
        listen: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:8750")]
        origin: String,
    },
    /// Host-owner compatibility interface (root or service account); not a logical-role client.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Host-owner compatibility interface (root or service account); not a logical-role client.
    Settings {
        #[command(subcommand)]
        command: Setting,
    },
    /// Host-owner compatibility interface (root or service account); not a logical-role client.
    Ha {
        #[command(subcommand)]
        command: Ha,
    },
    Tui {
        #[arg(long)]
        no_mouse: bool,
    },
    Install {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "light")]
        profile: Profile,
        #[arg(long, conflicts_with = "no_web")]
        web: bool,
        #[arg(long)]
        no_web: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        print_plan: bool,
        #[arg(long, default_value = "http://127.0.0.1:8750")]
        origin: String,
    },
    Health,
    /// Host-owner monitoring read from durable local history. Logical users use `user request`.
    Monitor {
        #[arg(long)]
        metric: Option<String>,
        #[arg(long, default_value_t = 3600)]
        seconds: u32,
    },
    /// Host-owner compatibility interface (root or service account); not a logical-role client.
    Retention {
        #[arg(long)]
        days: Option<u32>,
        #[arg(long)]
        budget_mib: Option<u64>,
        #[arg(long)]
        revision: Option<i64>,
        #[arg(long)]
        confirm_trim: bool,
    },
    Backup {
        #[command(subcommand)]
        command: Backup,
    },
    BackupInstall {
        #[arg(long)]
        managed_root: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        worker_binary: PathBuf,
        #[arg(long)]
        controller_config: PathBuf,
        #[arg(long)]
        apply_plan: Option<PathBuf>,
    },
    BackupRole {
        #[arg(long)]
        managed_root: PathBuf,
        #[arg(long)]
        apply_plan: Option<PathBuf>,
    },
    /// Host-owner compatibility interface (root or service account); not a logical-role client.
    BackupServer {
        #[command(subcommand)]
        command: BackupServer,
    },
    Broker {
        #[arg(long, default_value = "/var/lib/kagnode-daemon")]
        state: PathBuf,
        #[arg(long)]
        allowed_uid: u32,
    },
    /// Host-owner privileged broker client; not available to logical Managers or Viewers.
    Services {
        #[command(subcommand)]
        command: Services,
    },
}
#[derive(Subcommand)]
enum BackupServer {
    Status,
    Nodes,
    RotateCertificate {
        #[arg(long)]
        node: String,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long)]
        certificate_sha256: String,
    },
    Approve {
        #[arg(long)]
        node: String,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        certificate_sha256: String,
    },
    Revoke {
        #[arg(long)]
        node: String,
    },
    Snapshots {
        #[arg(long)]
        node: String,
    },
    Policy {
        #[arg(long)]
        file: PathBuf,
    },
    Pin {
        #[arg(long)]
        node: String,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        unpin: bool,
    },
    Delete {
        #[arg(long)]
        node: String,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        confirm: String,
    },
}
#[derive(Subcommand)]
enum Backup {
    Configure {
        #[arg(long)]
        directory: PathBuf,
    },
    Create {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, default_value = "/var/lib/kagnode-keys/daemon-backup.key")]
        key: PathBuf,
    },
    Validate {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        work: PathBuf,
    },
    Scheduled,
}
#[derive(Subcommand)]
enum Services {
    Enroll {
        #[arg(long)]
        product: String,
        #[arg(long)]
        unit: String,
    },
    Plan {
        #[arg(long)]
        product: String,
        #[arg(long, value_enum)]
        operation: kagnode_daemon::broker::Operation,
    },
    Apply {
        #[arg(long)]
        product: String,
        #[arg(long, value_enum)]
        operation: kagnode_daemon::broker::Operation,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long)]
        request_id: String,
    },
    Resolve {
        #[arg(long)]
        product: String,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        inspection_sha256: String,
        #[arg(long)]
        reason: String,
    },
}
#[derive(Subcommand)]
enum Setting {
    Show,
    Web {
        #[arg(value_parser=["on","off"])]
        value: String,
    },
}
#[derive(Subcommand)]
enum Ha {
    Plan {
        #[arg(long)]
        file: PathBuf,
    },
}
fn private_file(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>> {
    let m = path.symlink_metadata()?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.len() <= 4096,
        "Password file must be a private, owned regular file"
    );
    Ok(zeroize::Zeroizing::new(
        std::fs::read_to_string(path)?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    ))
}
fn prompt(message: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    tty.write_all(message.as_bytes())?;
    tty.flush()?;
    let mut line = String::new();
    std::io::BufReader::new(tty).read_line(&mut line)?;
    ensure!(line.len() <= 4096, "Input too long");
    Ok(line.trim().to_owned())
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(Command::User { action }) = &args.command {
        use std::io::Read;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        ensure!(
            unsafe { libc::fstat(libc::STDIN_FILENO, stat.as_mut_ptr()) } == 0,
            "Cannot inspect request input"
        );
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT == libc::S_IFREG {
            ensure!(
                stat.st_uid == unsafe { libc::geteuid() }
                    && stat.st_mode & 0o077 == 0
                    && stat.st_nlink == 1,
                "Credential request files must be private and owned by the caller"
            );
        }
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        std::io::stdin().take(16385).read_to_end(&mut raw)?;
        ensure!(raw.len() <= 16384, "Request exceeds 16 KiB");
        let request: kagnode_daemon::roles::Envelope = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("Invalid authenticated request"))?;
        let expected = match action.as_str() {
            "list" => "user_list".into(),
            "create" => "user_create".into(),
            "update" => "user_update".into(),
            "reset-password" => "user_reset_password".into(),
            other => other.replace('-', "_"),
        };
        ensure!(
            action == "request" || request.payload.name() == expected,
            "Subcommand and request action differ"
        );
        let result = kagnode_daemon::runtime::authenticated_request(&args.root, &request)?;
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }
    if let Some(Command::BackupInstall {
        managed_root,
        config,
        worker_binary,
        controller_config,
        apply_plan,
    }) = &args.command
    {
        use kagnode_daemon::backup_service::{role, transport};
        let result = if let Some(path) = apply_plan {
            let plan: role::Installation =
                serde_json::from_slice(&transport::read_file(path, true)?)?;
            ensure!(
                plan.root == *managed_root
                    && plan.unit_directory == std::path::Path::new("/etc/systemd/system"),
                "Installation root mismatch"
            );
            role::install(&plan)?
        } else {
            serde_json::to_value(role::installation_plan(
                managed_root,
                config,
                worker_binary,
                std::path::Path::new("/etc/systemd/system"),
                controller_config,
            )?)?
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    if let Some(Command::BackupRole {
        managed_root,
        apply_plan,
    }) = &args.command
    {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "Role reservation requires root"
        );
        use kagnode_daemon::backup_service::{role, transport};
        let result = if let Some(path) = apply_plan {
            role::apply(
                managed_root,
                &serde_json::from_slice(&transport::read_file(path, true)?)?,
            )?
        } else {
            serde_json::to_value(role::plan(managed_root)?)?
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    if let Some(Command::Install {
        email,
        password_file,
        profile,
        web,
        no_web,
        yes,
        print_plan,
        origin,
    }) = &args.command
    {
        let web = if *web {
            true
        } else if *no_web || *print_plan {
            false
        } else {
            prompt("Install the web dashboard? [y/N] ")?.eq_ignore_ascii_case("y")
        };
        let plan = kagnode_daemon::install::plan(*profile, web, origin)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        if *print_plan {
            return Ok(());
        }
        // Supplying an account on the command line means a protected install.
        let protect = email.is_some()
            || password_file.is_some()
            || !prompt(
                "Protect the Daemon with an Operator password?\n  Yes: every terminal and dashboard action is tied to a signed-in account.\n  No:  only this machine's owner can use the terminal, with no account, and the\n       Daemon is shown as unprotected. You can add a password later.\n[Y/n] ",
            )?
            .eq_ignore_ascii_case("n");
        if !protect {
            ensure!(
                prompt("Type owner to confirm an unprotected install: ")? == "owner",
                "Installation cancelled before provisioning"
            );
            anyhow::bail!(
                "Unprotected installation needs the installer's service-user support, which is not available yet. No changes were made; run again and choose a password."
            );
        }
        println!(
            "Operator: the first account. It manages everything and can add Managers (chosen services and levels) and Viewers (read-only analytics) from the terminal Users screen."
        );
        let email = if let Some(v) = email {
            v.clone()
        } else {
            prompt("Administrator email: ")?
        };
        let password = if let Some(path) = password_file {
            private_file(path)?
        } else {
            let first =
                zeroize::Zeroizing::new(rpassword::prompt_password("Administrator password: ")?);
            let second = zeroize::Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
            ensure!(*first == *second, "Passwords do not match");
            first
        };
        ensure!(
            *yes || prompt("Install the reviewed configuration? [y/N] ")?.eq_ignore_ascii_case("y"),
            "Installation cancelled before provisioning"
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&kagnode_daemon::install::apply(
                &email, &password, *profile, web, origin
            )?)?
        );
        return Ok(());
    }
    if let Some(Command::Backup { command }) = &args.command {
        use kagnode_daemon::backup;
        let value = match command {
            Backup::Configure { directory } => {
                kagnode_daemon::install::configure_backup(directory)?
            }
            Backup::Create { directory, key } => backup::create(&args.root, directory, key)?,
            Backup::Validate { file, key, work } => backup::validate(file, key, work)?,
            Backup::Scheduled => {
                let config = std::path::Path::new("/etc/kagnode/daemon/backup-destination");
                let m = config.symlink_metadata()?;
                ensure!(
                    m.uid() == 0
                        && m.mode() & 0o077 == 0
                        && !m.file_type().is_symlink()
                        && m.len() <= 4096,
                    "Unsafe backup destination configuration"
                );
                let directory = PathBuf::from(std::fs::read_to_string(config)?.trim());
                backup::create(
                    &args.root,
                    &directory,
                    std::path::Path::new("/var/lib/kagnode-keys/daemon-backup.key"),
                )?
            }
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    if let Some(Command::Broker { state, allowed_uid }) = &args.command {
        return kagnode_daemon::broker::serve(state, *allowed_uid).await;
    }
    if let Some(Command::Services { command }) = &args.command {
        use kagnode_daemon::broker::{self, Request};
        let value = match command {
            Services::Enroll { product, unit } => broker::enroll(product, unit).await?,
            Services::Plan { product, operation } => {
                broker::request(Request::Plan {
                    product: product.clone(),
                    operation: *operation,
                })
                .await?
            }
            Services::Apply {
                product,
                operation,
                expected_sha256,
                request_id,
            } => {
                broker::request(Request::Apply {
                    product: product.clone(),
                    operation: *operation,
                    expected_sha256: expected_sha256.clone(),
                    request_id: request_id.clone(),
                })
                .await?
            }
            Services::Resolve {
                product,
                request_id,
                inspection_sha256,
                reason,
            } => {
                broker::request(Request::Resolve {
                    product: product.clone(),
                    request_id: request_id.clone(),
                    inspection_sha256: inspection_sha256.clone(),
                    reason: reason.clone(),
                })
                .await?
            }
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    if matches!(
        args.command,
        Some(
            Command::Status { .. }
                | Command::Settings { .. }
                | Command::Ha { .. }
                | Command::Monitor { .. }
                | Command::Retention { .. }
                | Command::BackupServer { .. }
                | Command::Health
        )
    ) {
        require_host_owner(&args.root)?;
    }
    // Use the runtime owner for its database, even from a root terminal; avoid
    // creating root-owned SQLite journal files that strand the service account.
    if unsafe { libc::geteuid() } == 0 && args.root.exists() {
        let m = args.root.symlink_metadata()?;
        ensure!(!m.file_type().is_symlink(), "Unsafe state directory");
        if m.uid() != 0 {
            ensure!(
                unsafe { libc::setgroups(0, std::ptr::null()) } == 0
                    && unsafe { libc::setgid(m.gid()) } == 0
                    && unsafe { libc::setuid(m.uid()) } == 0,
                "Cannot enter the runtime account"
            );
        }
    }
    if matches!(args.command, Some(Command::Tui { .. }) | None) {
        // Sign in first: the terminal opens the local store only for Operators.
        let mouse = !matches!(args.command, Some(Command::Tui { no_mouse: true }));
        return kagnode_daemon::tui_gate::entry(&args.root, mouse);
    }
    let store = Store::open(&args.root)?;
    match args.command {
        Some(Command::InitOwner { profile }) => {
            kagnode_daemon::roles::init_owner(&store, unsafe { libc::geteuid() }, profile)?;
            println!(
                "Owner mode initialized: unprotected, local-only, web administration disabled."
            );
        }
        Some(Command::Init {
            email,
            password_file,
            profile,
            web,
        }) => {
            store.init(&email, &private_file(&password_file)?, profile, web)?;
            println!(
                "Local administrator initialized. Existing application data was not modified."
            );
        }
        Some(Command::Status { json: _ }) => {
            let settings = store.settings()?;
            let root = store.managed_root();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"product":"KagNode. Daemon","version":env!("CARGO_PKG_VERSION"),"settings":settings,"applications":catalog::PRODUCTS.iter().map(|p|json!({"product":p,"installed":catalog::installed(root,p)})).collect::<Vec<_>>()})
                )?
            );
        }
        Some(Command::Settings {
            command: Setting::Show,
        }) => println!("{}", serde_json::to_string_pretty(&store.settings()?)?),
        Some(Command::Settings {
            command: Setting::Web { value },
        }) => {
            let mut s = store.settings()?;
            s.web_enabled = value == "on";
            store.set_settings("local-terminal", s)?;
            println!(
                "Dashboard preference saved. Enabling takes effect when the Daemon starts; disabling closes its HTTP listener."
            );
        }
        Some(Command::Ha {
            command: Ha::Plan { file },
        }) => {
            ensure!(
                std::fs::metadata(&file)?.len() <= 65536,
                "Cluster declaration is too large"
            );
            let c: kagnode_daemon::ha::Cluster = serde_json::from_slice(&std::fs::read(file)?)?;
            println!("{}", serde_json::to_string_pretty(&c.plan()?)?);
        }
        Some(Command::Serve { listen, origin }) => {
            ensure!(
                listen.ip().is_loopback(),
                "Bind the dashboard to loopback and configure a trusted HTTPS reverse proxy for remote access"
            );
            ensure!(
                origin.starts_with("https://") || origin == format!("http://{listen}"),
                "Use HTTPS for a remote dashboard origin"
            );
            let url = reqwest::Url::parse(&origin)?;
            ensure!(
                url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.username().is_empty()
                    && url.password().is_none(),
                "Configure an origin without a path, query or credentials"
            );
            let app = App {
                store: store.clone(),
                origin: origin.trim_end_matches('/').to_owned(),
                core: Arc::new(
                    kagnode_core::Core::new("/srv/kagnode/core", "daemon")
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?,
                ),
            };
            let store_root_socket = store.root.join("run/control.sock");
            let run = store.root.join("run");
            std::fs::create_dir_all(&run)?;
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))?;
            let socket = run.join("daemon.sock");
            if socket.exists() {
                ensure!(
                    std::os::unix::net::UnixStream::connect(&socket).is_err(),
                    "Daemon is already running"
                );
                ensure!(
                    socket.symlink_metadata()?.file_type().is_socket(),
                    "Unexpected socket path"
                );
                std::fs::remove_file(&socket)?;
            }
            let listener = tokio::net::UnixListener::bind(&socket)?;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
            let mut terminal_api = tokio::spawn(kagnode_daemon::runtime::serve(store.clone()));
            let collector = tokio::spawn(kagnode_daemon::runtime::collect(store.clone()));
            let mut backup_server = tokio::spawn(
                kagnode_daemon::backup_service::supervisor::supervise(store.clone()),
            );
            let mut backup_agent = tokio::spawn(
                kagnode_daemon::backup_service::scheduler::supervise(store.clone()),
            );
            let local = web::router(app.clone());
            let mut task = tokio::spawn(async move { axum::serve(listener, local).await });
            let web_store = store.clone();
            let mut web_task = tokio::spawn(async move {
                if web_store.settings()?.web_enabled {
                    let listener = tokio::net::TcpListener::bind(listen).await?;
                    println!("Daemon dashboard listening on {listen}; origin {origin}");
                    axum::serve(
                        listener,
                        web::router(app).into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(async move {
                        while web_store.settings().is_ok_and(|s| s.web_enabled) {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    })
                    .await?;
                } else {
                    println!(
                        "Daemon running with dashboard disabled; private local socket available"
                    );
                }
                Ok::<(), anyhow::Error>(())
            });
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut web_finished = false;
            let result: Result<()> = loop {
                tokio::select! {
                    r = tokio::signal::ctrl_c() => break r.map_err(Into::into),
                    _ = terminate.recv() => break Ok(()),
                    r = &mut backup_agent => break Err(anyhow::anyhow!("Backup agent stopped: {r:?}")),
                    r = &mut backup_server => break Err(anyhow::anyhow!("Backup supervisor stopped: {r:?}")),
                    r = &mut terminal_api => break Err(anyhow::anyhow!("Terminal API stopped: {r:?}")),
                    r = &mut task => break Err(anyhow::anyhow!("Local health API stopped: {r:?}")),
                    r = &mut web_task, if !web_finished => match r {
                        Ok(Ok(())) => web_finished = true,
                        other => break Err(anyhow::anyhow!("Dashboard listener failed: {other:?}")),
                    },
                }
            };
            web_task.abort();
            task.abort();
            terminal_api.abort();
            collector.abort();
            backup_server.abort();
            backup_agent.abort();
            let _ = std::fs::remove_file(store_root_socket);
            std::fs::remove_file(socket)?;
            result?;
        }
        Some(Command::Monitor { metric, seconds }) => {
            ensure!(
                (10..=31_536_000).contains(&seconds),
                "History window must be 10 seconds–365 days"
            );
            let now = kagnode_daemon::auth::now();
            let query = match metric {
                Some(name) => kagnode_daemon::runtime::Request::Metrics {
                    name,
                    since: now - i64::from(seconds),
                    until: now,
                },
                None => kagnode_daemon::runtime::Request::Overview,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&kagnode_daemon::runtime::dispatch_as(
                    &store,
                    query,
                    "host-owner-cli"
                )?)?
            );
        }
        Some(Command::Retention {
            days,
            budget_mib,
            revision,
            confirm_trim,
        }) => {
            use kagnode_daemon::{metrics::Policy, runtime};
            let value =
                runtime::dispatch_as(&store, runtime::Request::Retention, "host-owner-cli")?;
            let result = if days.is_some() || budget_mib.is_some() {
                let mut policy: Policy = serde_json::from_value(value["policy"].clone())?;
                if let Some(days) = days {
                    policy.days = days;
                }
                if let Some(mib) = budget_mib {
                    policy.budget_bytes = mib
                        .checked_mul(1024 * 1024)
                        .ok_or_else(|| anyhow::anyhow!("Budget overflow"))?;
                }
                let revision = revision.ok_or_else(|| {
                    anyhow::anyhow!("Read retention first and supply its --revision")
                })?;
                runtime::dispatch_as(
                    &store,
                    runtime::Request::SetRetention {
                        revision,
                        policy,
                        confirm_trim,
                    },
                    "host-owner-cli",
                )?
            } else {
                value
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some(Command::BackupServer { command }) => {
            use kagnode_daemon::backup_service::{control::AdminRequest, transport};
            let request = match command {
                BackupServer::Status => AdminRequest::Status,
                BackupServer::Nodes => AdminRequest::Nodes,
                BackupServer::RotateCertificate {
                    node,
                    expected_sha256,
                    certificate_sha256,
                } => AdminRequest::RotateCertificate {
                    node,
                    expected_sha256,
                    certificate_sha256,
                },
                BackupServer::Approve {
                    node,
                    public_key,
                    certificate_sha256,
                } => AdminRequest::Approve {
                    node,
                    public_key,
                    certificate_sha256,
                },
                BackupServer::Revoke { node } => AdminRequest::Revoke { node },
                BackupServer::Snapshots { node } => AdminRequest::Snapshots { node },
                BackupServer::Policy { file } => AdminRequest::SetPolicy {
                    policy: serde_json::from_slice(&transport::read_file(&file, true)?)?,
                },
                BackupServer::Pin {
                    node,
                    snapshot,
                    unpin,
                } => AdminRequest::Pin {
                    node,
                    snapshot,
                    pinned: !unpin,
                },
                BackupServer::Delete {
                    node,
                    snapshot,
                    confirm,
                } => AdminRequest::Delete {
                    node,
                    snapshot,
                    confirm,
                },
            };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &kagnode_daemon::backup_service::supervisor::request(&store, &request).await?
                )?
            );
        }
        Some(Command::Health) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut socket =
                tokio::net::UnixStream::connect(store.root.join("run/daemon.sock")).await?;
            socket
                .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await?;
            let mut reply = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.take(16384).read_to_string(&mut reply),
            )
            .await??;
            ensure!(
                reply.starts_with("HTTP/1.0 200") || reply.starts_with("HTTP/1.1 200"),
                "Daemon health check failed"
            );
            println!("Daemon local health is OK");
        }
        Some(
            Command::User { .. }
            | Command::Broker { .. }
            | Command::Services { .. }
            | Command::BackupInstall { .. }
            | Command::BackupRole { .. }
            | Command::Install { .. }
            | Command::Backup { .. },
        ) => unreachable!(),
        Some(Command::Tui { .. }) | None => unreachable!("handled before the store opens"),
    }
    Ok(())
}

fn require_host_owner(root: &std::path::Path) -> Result<()> {
    let m = root.symlink_metadata().map_err(|_| anyhow::anyhow!("Host-owner command requires an existing installation; logical users use kagnode user request"))?;
    ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && (unsafe { libc::geteuid() } == 0 || m.uid() == unsafe { libc::geteuid() }),
        "Host-owner command requires root or the runtime account; logical users use kagnode user request"
    );
    Ok(())
}
