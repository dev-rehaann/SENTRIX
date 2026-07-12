//! `sentrix-verify`: a read-only, independent forensic verifier.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use sentrix_verifier_cli::{anchor, chain};

#[derive(Debug, Parser)]
#[command(name = "sentrix-verify", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify every canonical record, hash link, and Ed25519 signature.
    Chain {
        /// Path to the canonical JSONL chain.
        chain: PathBuf,
        /// Raw 32-byte or 64-character lowercase-hex Ed25519 public key file.
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Run the partial anchor check; this is not a chain-integrity verdict.
    Anchor {
        /// Path to the canonical JSONL chain.
        chain: PathBuf,
        /// Path to a detached OpenTimestamps proof.
        #[arg(long)]
        ots_proof: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::Chain { chain, pubkey } => {
            let public_key = read_public_key(&pubkey)?;
            let report =
                chain::verify_path(&chain, &public_key).map_err(|error| error.to_string())?;
            let tip = report.tip.map_or_else(
                || "none (empty chain)".to_owned(),
                |tip| format!("seq {}, {}", tip.seq, tip.record_hash),
            );
            Ok(format!(
                "chain valid: {} record(s); tip {tip}",
                report.records
            ))
        }
        Command::Anchor { chain, ots_proof } => {
            anchor::verify_anchor(&chain, &ots_proof).map_err(|error| {
                format!(
                    "anchor check incomplete: {error}\n\
                     IMPORTANT: this non-zero exit does NOT mean the chain is corrupt or tampered. \
                     The `chain` subcommand is the chain-integrity verdict. Full anchor verification \
                     requires an independently trusted Bitcoin Core node and a mature Rust OTS proof-verification crate."
                )
            })?;
            Ok("anchor valid".to_owned())
        }
    }
}

fn read_public_key(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read public key: {error}"))?;
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| "public key must contain exactly 32 raw bytes".to_owned());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "public key must be 32 raw bytes or lowercase hexadecimal UTF-8".to_owned())?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    chain::decode_hex_array::<32>(text).map_err(|reason| format!("invalid public key: {reason}"))
}
