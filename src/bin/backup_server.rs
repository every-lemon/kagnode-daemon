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
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
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
            let tls = transport::tls(&config)?;
            let shared: Shared = Arc::new(Mutex::new(Repository::open(&config.repository)?));
            let listener = tokio::net::TcpListener::bind(config.listen).await?;
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {result=transport::serve(listener,tls,shared.clone())=>result?,result=control::serve(&config.control_socket,shared)=>result?,result=tokio::signal::ctrl_c()=>result?,_=terminate.recv()=>{}}
        }
    }
    Ok(())
}
