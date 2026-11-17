//! Maintainer-only candidate builder. No installation or publishing interface.
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "kagnode-release",
    version,
    about = "Build and verify signed, unqualified Rust Daemon candidates"
)]
struct Args {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Build {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        work: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "x86_64-unknown-linux-gnu")]
        target: String,
        /// Read-only inherited descriptor for the established private signing identity.
        #[arg(long)]
        signing_fd: i32,
    },
    Verify {
        #[arg(long)]
        directory: PathBuf,
    },
}
fn main() -> Result<()> {
    match Args::parse().action {
        Action::Build {
            source,
            work,
            output,
            target,
            signing_fd,
        } => println!(
            "{}",
            serde_json::to_string_pretty(&kagnode_daemon::release::build(
                &kagnode_daemon::release::BuildOptions {
                    source,
                    work,
                    output,
                    target,
                    signing_fd
                }
            )?)?
        ),
        Action::Verify { directory } => {
            let m = kagnode_daemon::release::verify(&directory)?;
            println!(
                "{}",
                serde_json::json!({"verified":true,"source":m.source_commit,"version":m.version,"runtime":m.runtime,"production_eligible":m.production_eligible})
            );
        }
    };
    Ok(())
}
