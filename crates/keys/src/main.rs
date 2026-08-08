//! `airgap-keys` — CLI for M2 key management (PLAN.md §5.5).
//!
//! Software-backed key storage (HSM is the future target). Signing keys are
//! never exposed to sandbox VMs; this CLI runs on the core VM / Update Server
//! only. See `keys/KEY-MANAGEMENT.md`.

use std::fs;
use std::path::PathBuf;

use airgap_keys::{KeyManager, KeyRole};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "airgap-keys", about = "air-gap pipeline key management (M2)")]
struct Cli {
    /// Key manager directory
    #[arg(long, default_value = "./keys")]
    dir: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Provision a signing key for a role (no overwrite by default)
    Provision {
        #[arg(value_enum)]
        role: KeyRoleArg,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long)]
        overwrite: bool,
    },
    /// Sign a file with a role's key -> base64 signature to stdout
    Sign {
        #[arg(value_enum)]
        role: KeyRoleArg,
        file: PathBuf,
    },
    /// Verify a file against a signature
    Verify {
        #[arg(value_enum)]
        role: KeyRoleArg,
        file: PathBuf,
        sig: String,
    },
    /// Print a role's public key as base64 (for a rotation USB trip)
    ExportPub {
        #[arg(value_enum)]
        role: KeyRoleArg,
    },
    /// Import a role's public key from base64
    ImportPub {
        #[arg(value_enum)]
        role: KeyRoleArg,
        pubkey_b64: String,
        #[arg(long, default_value = "imported")]
        note: String,
    },
    /// Print stored metadata for a role
    Metadata {
        #[arg(value_enum)]
        role: KeyRoleArg,
    },
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum KeyRoleArg {
    Export,
    Release,
}

impl From<KeyRoleArg> for KeyRole {
    fn from(r: KeyRoleArg) -> Self {
        match r {
            KeyRoleArg::Export => KeyRole::Export,
            KeyRoleArg::Release => KeyRole::Release,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut km = KeyManager::new(&cli.dir)?;
    if matches!(cli.cmd, Cmd::Provision { overwrite: true, .. }) {
        km = km.allow_overwrite();
    }

    match &cli.cmd {
        Cmd::Provision { role, note, .. } => {
            let role: KeyRole = (*role).into();
            let (_sk, _vk) = km.provision(role, note)?;
            println!("provisioned {} key in {}", role.as_str(), cli.dir.display());
            println!("public key b64: {}", km.export_public_key_b64(role)?);
        }
        Cmd::Sign { role, file } => {
            let role: KeyRole = (*role).into();
            let data = fs::read(file)?;
            let sig = km.sign(role, &data)?;
            println!("{sig}");
        }
        Cmd::Verify { role, file, sig } => {
            let role: KeyRole = (*role).into();
            let data = fs::read(file)?;
            km.verify(role, &data, sig)?;
            println!("OK: signature valid");
        }
        Cmd::ExportPub { role } => {
            let role: KeyRole = (*role).into();
            println!("{}", km.export_public_key_b64(role)?);
        }
        Cmd::ImportPub { role, pubkey_b64, note } => {
            let role: KeyRole = (*role).into();
            km.import_public_key_b64(role, pubkey_b64, note)?;
            println!("imported {} public key", role.as_str());
        }
        Cmd::Metadata { role } => {
            let role: KeyRole = (*role).into();
            let meta = km.metadata(role)?;
            println!("{}", serde_json::to_string_pretty(&meta)?);
        }
    }
    Ok(())
}
