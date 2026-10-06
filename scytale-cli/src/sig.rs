//! `scytale sig`: signing a message and checking a signature.
//!
//! The scheme is named on the call and the key file must hold a key
//! for it: `ed25519`; `ecdsa-HASH` on a P-256, P-384 or P-521 key;
//! `rsa-pss-HASH` on an RSA or RSA-PSS key; `rsa-pkcs1-HASH` on an
//! RSA key; the ML-DSA and SLH-DSA sets by their own names.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::Algorithm;
use scytale::random::CtrDrbg;
use scytale::sig::{ecdsa, ed25519, rsa};

use crate::fail::{Result, usage, verify};
use crate::hash::with_hash;
use crate::io::Format;
use crate::key::{self, with_pq_sig};
use crate::{io, names, value};

#[derive(Subcommand)]
pub enum SigOp {
    /// Sign the input with a private key
    Sign(SignArgs),
    /// Check a signature over the input with a public key
    Verify(VerifyArgs),
}

impl SigOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            SigOp::Sign(a) => format!("sign {}", a.scheme),
            SigOp::Verify(a) => format!("verify {}", a.scheme),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct SignArgs {
    /// The scheme: ed25519, ecdsa-sha256, rsa-pss-sha256, ml-dsa-65, ...
    pub scheme: String,
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// The context string, for ed25519, ml-dsa and slh-dsa
    #[arg(long)]
    context: Option<String>,
    /// Write an ECDSA signature as r || s rather than DER
    #[arg(long)]
    raw_ecdsa: bool,
    /// Raw bytes by default
    #[command(flatten)]
    format: Format,
    /// The file to sign; standard input without one
    file: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct VerifyArgs {
    /// The scheme: ed25519, ecdsa-sha256, rsa-pss-sha256, ml-dsa-65, ...
    pub scheme: String,
    /// The public key file (PEM)
    #[arg(short, long)]
    public: PathBuf,
    /// The signature (hex:, file:, fd:, env:)
    #[arg(short, long)]
    signature: String,
    /// The context string, for ed25519, ml-dsa and slh-dsa
    #[arg(long)]
    context: Option<String>,
    /// Read an ECDSA signature as r || s rather than DER
    #[arg(long)]
    raw_ecdsa: bool,
    /// The signed file; standard input without one
    file: Option<PathBuf>,
}

/// What a scheme name resolves to.
enum Scheme {
    Ed25519,
    Ecdsa(&'static str),
    RsaPss(&'static str),
    RsaPkcs1(&'static str),
    PostQuantum(Algorithm),
}

impl Scheme {
    fn parse(name: &str) -> Result<(Self, &'static str)> {
        let entry = names::SIG.find(name)?;
        let name = entry.name;
        let scheme = if name == "ed25519" {
            Scheme::Ed25519
        } else if let Some(h) = name.strip_prefix("ecdsa-") {
            Scheme::Ecdsa(h)
        } else if let Some(h) = name.strip_prefix("rsa-pss-") {
            Scheme::RsaPss(h)
        } else if let Some(h) = name.strip_prefix("rsa-pkcs1-") {
            Scheme::RsaPkcs1(h)
        } else if let Some(a) = key::pq_by_name(name) {
            Scheme::PostQuantum(a)
        } else {
            return Err(usage!("no signature scheme named \"{name}\""));
        };
        Ok((scheme, name))
    }

    /// The key algorithms this scheme runs on.
    fn keys(&self) -> Vec<Algorithm> {
        match self {
            Scheme::Ed25519 => vec![Algorithm::Ed25519],
            Scheme::Ecdsa(_) => {
                vec![Algorithm::P256, Algorithm::P384, Algorithm::P521]
            }
            Scheme::RsaPss(_) => vec![Algorithm::Rsa, Algorithm::RsaPss],
            Scheme::RsaPkcs1(_) => vec![Algorithm::Rsa],
            Scheme::PostQuantum(a) => vec![*a],
        }
    }

    /// Whether `--context` is meaningful.
    fn takes_context(&self) -> bool {
        matches!(self, Scheme::Ed25519 | Scheme::PostQuantum(_))
    }

    fn takes_raw_ecdsa(&self) -> bool {
        matches!(self, Scheme::Ecdsa(_))
    }
}

pub fn run(op: SigOp) -> Result<()> {
    match op {
        SigOp::Sign(args) => sign(args),
        SigOp::Verify(args) => verify(args),
    }
}

fn options(
    scheme: &Scheme,
    name: &str,
    context: bool,
    raw_ecdsa: bool,
) -> Result<()> {
    if context && !scheme.takes_context() {
        return Err(usage!(
            "{name} takes no --context; that is for ed25519, ml-dsa and \
             slh-dsa"
        ));
    }
    if raw_ecdsa && !scheme.takes_raw_ecdsa() {
        return Err(usage!("{name} takes no --raw-ecdsa; that is for ecdsa"));
    }
    Ok(())
}

fn sign(args: SignArgs) -> Result<()> {
    let (scheme, name) = Scheme::parse(&args.scheme)?;
    options(&scheme, name, args.context.is_some(), args.raw_ecdsa)?;
    let pem = key::read_private(&args.key, &scheme.keys(), name)?;
    let info = scytale::KeyInfo::try_from_pem(&pem)?;
    let message = io::read_all(args.file.as_deref())?;
    let context = value::text(args.context.as_deref(), "--context")?;
    let signature: Vec<u8> = match scheme {
        Scheme::Ed25519 => {
            let key = ed25519::PrivateKey::try_from_pem(&pem)?;
            match &args.context {
                Some(_) => key.sign_ctx(&context, &message)?.to_vec(),
                None => key.sign(&message).to_vec(),
            }
        }
        Scheme::Ecdsa(hash) => match info.algorithm {
            Algorithm::P256 => {
                let key = ecdsa::p256::PrivateKey::try_from_pem(&pem)?;
                let sig = with_hash!(hash, H => Ok(key.sign::<H>(&message)?))?;
                if args.raw_ecdsa {
                    sig.to_vec()
                } else {
                    let mut der = [0u8; 128];
                    let n = ecdsa::p256::signature_der(&sig, &mut der)?;
                    der[..n].to_vec()
                }
            }
            Algorithm::P384 => {
                let key = ecdsa::p384::PrivateKey::try_from_pem(&pem)?;
                let sig = with_hash!(hash, H => Ok(key.sign::<H>(&message)?))?;
                if args.raw_ecdsa {
                    sig.to_vec()
                } else {
                    let mut der = [0u8; 128];
                    let n = ecdsa::p384::signature_der(&sig, &mut der)?;
                    der[..n].to_vec()
                }
            }
            _ => {
                let key = ecdsa::p521::PrivateKey::try_from_pem(&pem)?;
                let sig = with_hash!(hash, H => Ok(key.sign::<H>(&message)?))?;
                if args.raw_ecdsa {
                    sig.to_vec()
                } else {
                    let mut der = [0u8; 160];
                    let n = ecdsa::p521::signature_der(&sig, &mut der)?;
                    der[..n].to_vec()
                }
            }
        },
        Scheme::RsaPss(hash) => {
            let key = rsa::PrivateKey::try_from_pem(&pem)?;
            let mut rng = CtrDrbg::from_system()?;
            let sig = with_hash!(hash, H => {
                Ok(key.sign_pss::<H, _>(&mut rng, &message)?)
            })?;
            sig.as_ref().to_vec()
        }
        Scheme::RsaPkcs1(hash) => {
            let key = rsa::PrivateKey::try_from_pem(&pem)?;
            let sig =
                with_hash!(hash, H => Ok(key.sign_pkcs1::<H>(&message)?))?;
            sig.as_ref().to_vec()
        }
        Scheme::PostQuantum(a) => with_pq_sig!(a, m => {
            let key = m::PrivateKey::try_from_pem(&pem)?;
            let mut rng = CtrDrbg::from_system()?;
            key.sign(&mut rng, &context, &message)
                .map_err(|_| usage!(
                    "--context is {} bytes; at most 255",
                    context.len()
                ))?
                .to_vec()
        }, _ => return Err(usage!("{a} is not a signature scheme"))),
    };
    let mut out = io::output(args.out.as_deref(), false)?;
    io::write(&mut *out, &signature, args.format.as_hex(false))
}

fn verify(args: VerifyArgs) -> Result<()> {
    let (scheme, name) = Scheme::parse(&args.scheme)?;
    options(&scheme, name, args.context.is_some(), args.raw_ecdsa)?;
    let pem = key::read_public(&args.public, &scheme.keys(), name)?;
    let info = scytale::KeyInfo::try_from_pem(&pem)?;
    let message = io::read_all(args.file.as_deref())?;
    let context = value::text(args.context.as_deref(), "--context")?;
    let signature = value::parse(&args.signature, "--signature", false)?;
    let fixed = |n: usize| -> Result<&[u8]> {
        value::check(&signature, names::Len::Exact(n), "--signature", name)?;
        Ok(&signature[..])
    };
    let invalid = || {
        verify!(
            "the signature is not valid for this message under {}",
            args.public.display()
        )
    };
    let result = match scheme {
        Scheme::Ed25519 => {
            let key = ed25519::PublicKey::try_from_pem(&pem)?;
            let sig = fixed(ed25519::SIGNATURE_SIZE)?;
            let sig = sig.try_into().map_err(|_| invalid())?;
            match &args.context {
                Some(_) => key.verify_ctx(&context, &message, sig),
                None => key.verify(&message, sig),
            }
        }
        Scheme::Ecdsa(hash) => {
            let der = |e: scytale::Error| match e {
                scytale::Error::InvalidEncoding => usage!(
                    "--signature is not a DER ECDSA signature ({} bytes); \
                     for r || s say --raw-ecdsa",
                    signature.len()
                ),
                other => other.into(),
            };
            match info.algorithm {
                Algorithm::P256 => {
                    let key = ecdsa::p256::PublicKey::try_from_pem(&pem)?;
                    let sig = if args.raw_ecdsa {
                        let sig = fixed(ecdsa::p256::SIGNATURE_SIZE)?;
                        sig.try_into().map_err(|_| invalid())?
                    } else {
                        ecdsa::p256::signature_from_der(&signature)
                            .map_err(der)?
                    };
                    with_hash!(hash, H => Ok(key.verify::<H>(&message, &sig)))?
                }
                Algorithm::P384 => {
                    let key = ecdsa::p384::PublicKey::try_from_pem(&pem)?;
                    let sig = if args.raw_ecdsa {
                        let sig = fixed(ecdsa::p384::SIGNATURE_SIZE)?;
                        sig.try_into().map_err(|_| invalid())?
                    } else {
                        ecdsa::p384::signature_from_der(&signature)
                            .map_err(der)?
                    };
                    with_hash!(hash, H => Ok(key.verify::<H>(&message, &sig)))?
                }
                _ => {
                    let key = ecdsa::p521::PublicKey::try_from_pem(&pem)?;
                    let sig = if args.raw_ecdsa {
                        let sig = fixed(ecdsa::p521::SIGNATURE_SIZE)?;
                        sig.try_into().map_err(|_| invalid())?
                    } else {
                        ecdsa::p521::signature_from_der(&signature)
                            .map_err(der)?
                    };
                    with_hash!(hash, H => Ok(key.verify::<H>(&message, &sig)))?
                }
            }
        }
        Scheme::RsaPss(hash) => {
            let key = rsa::PublicKey::try_from_pem(&pem)?;
            fixed(key.modulus_len())?;
            with_hash!(hash, H => {
                Ok(key.verify_pss::<H>(&message, &signature))
            })?
        }
        Scheme::RsaPkcs1(hash) => {
            let key = rsa::PublicKey::try_from_pem(&pem)?;
            fixed(key.modulus_len())?;
            with_hash!(hash, H => {
                Ok(key.verify_pkcs1::<H>(&message, &signature))
            })?
        }
        Scheme::PostQuantum(a) => with_pq_sig!(a, m => {
            let key = m::PublicKey::try_from_pem(&pem)?;
            let sig = fixed(m::SIGNATURE_SIZE)?;
            let sig = sig.try_into().map_err(|_| invalid())?;
            key.verify(&context, &message, sig)
        }, _ => return Err(usage!("{a} is not a signature scheme"))),
    };
    result.map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name in the table parses to a scheme.
    #[test]
    fn table_matches_dispatch() {
        for entry in names::SIG.iter() {
            let (scheme, name) = Scheme::parse(entry.name).unwrap();
            assert_eq!(name, entry.name);
            assert!(!scheme.keys().is_empty(), "{name}");
        }
    }
}
