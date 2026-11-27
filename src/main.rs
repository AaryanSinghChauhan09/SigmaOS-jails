#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sigma-jail", about = "SigmaOS Jails — lightweight process & filesystem isolation")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    List,
    Status,
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::List => println!("sigma-jail: no active jails configured."),
        Commands::Status => println!("sigma-jail: isolation subsystem ready."),
    }
}
