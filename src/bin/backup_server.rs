use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use kagnode_daemon::backup_service::{
    control::{self, AdminRequest},
    policy::Policy,
    repository::Repository,
    transport::{self, Config, Shared},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
#[derive(Parser)]
#[command(
    version,
    about = "KagNode Daemon backup server — experimental, unprivileged storage process"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        site: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        policy: PathBuf,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    Control {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
}
fn main() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } == 0,
        "Cannot close inherited descriptors"
    );
    if args.get(1).is_none_or(|arg| arg != "__isolated") {
        // Re-exec also removes inherited environment strings from process memory.
        return Err(std::process::Command::new(std::env::current_exe()?)
            .env_clear()
            .arg("__isolated")
            .args(args.iter().skip(1))
            .exec()
            .into());
    }
    ensure!(
        std::env::vars_os().next().is_none(),
        "Isolated worker must have an empty environment"
    );
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run())
}
async fn run() -> Result<()> {
    let args = Args::parse_from(
        std::env::args_os()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, a)| a),
    );
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Run the backup process as its dedicated unprivileged service account"
    );
    match args.command {
        Command::Init {
            directory,
            site,
            server,
            policy,
        } => {
            let policy: Policy = serde_json::from_slice(&transport::read_file(&policy, true)?)?;
            Repository::create(&directory, &site, &server, &policy)?;
            println!("Repository initialized; no service or schedule activated");
        }
        Command::Control { socket, request } => {
            let request: AdminRequest =
                serde_json::from_slice(&transport::read_file(&request, true)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&control::request(&socket, &request).await?)?
            );
        }
        Command::Serve { config } => {
            let config = Config::load(&config)?;
            ensure!(
                config
                    .controller_uid
                    .is_some_and(|uid| uid != 0 && uid != unsafe { libc::geteuid() }),
                "Backup worker needs a separate service account from its controller"
            );
            ensure!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
                "Cannot restrict worker privileges"
            );
            let tls = transport::tls(&config)?;
            let shared: Shared = Arc::new(Mutex::new(Repository::open(&config.repository)?));
            let listener = tokio::net::TcpListener::bind(config.listen).await?;
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {result=transport::serve(listener,tls,shared.clone())=>result?,result=control::serve_for(&config.control_socket,shared,config.controller_uid.unwrap())=>result?,result=tokio::signal::ctrl_c()=>result?,_=terminate.recv()=>{}}
        }
    }
    Ok(())
}
