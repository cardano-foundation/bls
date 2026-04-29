//! CLI implementation for BLS12-381 Aiken

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generates 32 bytes secret seed
    GenerateSeed,

    /// Derives PrivateKey from seed (stdin or --file)
    Hkdf(cmd::hkdf::Args),

    /// Converts private key to scalar (stdin or --file)
    Scalar(cmd::scalar::Args),

    /// Generates public key from private key (stdin or --file)
    Pk(cmd::pk::Args),

    /// Generates BLS signature from private key and message (stdin/file + --msg)
    Sig(cmd::sig::Args),
}

#[derive(Debug, Parser)]
#[clap(name = "bls12-381-aiken-cli")]
#[clap(bin_name = "bls-aiken")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version=env!("CARGO_PKG_VERSION"))]
#[clap(about = "BLS12-381 Aiken CLI tool")]
#[clap(about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::GenerateSeed => cmd::generate_seed::run(),
        Command::Hkdf(args) => cmd::hkdf::run(args),
        Command::Scalar(args) => cmd::scalar::run(args),
        Command::Pk(args) => cmd::pk::run(args),
        Command::Sig(args) => cmd::sig::run(args),
    }
}
