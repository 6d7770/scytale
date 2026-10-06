//! `scytale kex`: a shared secret from a private key and a peer's
//! public one.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::Algorithm;
use scytale::kex::{ecdh, x25519};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::io::Format;
use crate::{io, key, names};

#[derive(Subcommand)]
pub enum KexOp {
    /// The shared secret between a private key and a peer's public key
    Agree(AgreeArgs),
}

impl KexOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        let KexOp::Agree(a) = self;
        format!("agree {}", a.algorithm)
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct AgreeArgs {
    /// The agreement: x25519, ecdh-p256, ecdh-p384, ecdh-p521
    pub algorithm: String,
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// The peer's public key file (PEM), for the same curve
    #[arg(short, long)]
    peer: PathBuf,
    /// Hex by default
    #[command(flatten)]
    format: Format,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(op: KexOp) -> Result<()> {
    let KexOp::Agree(args) = op;
    let name = names::KEX.find(&args.algorithm)?.name;
    let algorithm = match name {
        "x25519" => Algorithm::X25519,
        "ecdh-p256" => Algorithm::P256,
        "ecdh-p384" => Algorithm::P384,
        "ecdh-p521" => Algorithm::P521,
        other => return Err(usage!("no key agreement named \"{other}\"")),
    };
    let private = key::read_private(&args.key, &[algorithm], name)?;
    let public = key::read_public(&args.peer, &[algorithm], name)?;
    let secret: Zeroizing<Vec<u8>> = match algorithm {
        Algorithm::X25519 => {
            let private = x25519::PrivateKey::try_from_pem(&private)?;
            let public = x25519::PublicKey::try_from_pem(&public)?;
            let secret = private.shared_secret(&public).map_err(|_| {
                usage!(
                    "{}: this public key gives a shared secret anyone can \
                     compute; refuse the peer",
                    args.peer.display()
                )
            })?;
            Zeroizing::new(secret.to_vec())
        }
        Algorithm::P256 => {
            let private = ecdh::p256::PrivateKey::try_from_pem(&private)?;
            let public = ecdh::p256::PublicKey::try_from_pem(&public)?;
            Zeroizing::new(private.shared_secret(&public).to_vec())
        }
        Algorithm::P384 => {
            let private = ecdh::p384::PrivateKey::try_from_pem(&private)?;
            let public = ecdh::p384::PublicKey::try_from_pem(&public)?;
            Zeroizing::new(private.shared_secret(&public).to_vec())
        }
        _ => {
            let private = ecdh::p521::PrivateKey::try_from_pem(&private)?;
            let public = ecdh::p521::PublicKey::try_from_pem(&public)?;
            Zeroizing::new(private.shared_secret(&public).to_vec())
        }
    };
    let mut out = io::output(args.out.as_deref(), true)?;
    io::write(&mut *out, &secret, args.format.as_hex(true))
}
