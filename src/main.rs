use anyhow::Result;
use clap::Parser;

mod attack;
mod error;

use clap::Subcommand;
use pnet::datalink;

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    #[clap(name("drop"), about("Drop traffic between target and gateway"))]
    DropTraffic(attack::Command),
    #[clap(about("List network interfaces"))]
    ListInterfaces,
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    commands: Subcommands,
}

fn main() -> Result<()> {
    match Cli::parse().commands {
        Subcommands::ListInterfaces => {
            println!(
                "{}",
                datalink::interfaces()
                    .iter()
                    .map(|interface| format!("{}: {}", interface.index, interface.description))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        Subcommands::DropTraffic(drop_traffic) => drop_traffic.drop_traffic()?,
    }
    Ok(())
}
