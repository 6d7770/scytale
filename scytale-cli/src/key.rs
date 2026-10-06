//! `scytale key`: making, reading and describing key files.
//!
//! Keys travel as PEM, the private half as a `PRIVATE KEY` block
//! (PKCS#8) and the public half as `PUBLIC KEY`, which is what every
//! other tool reads and writes. The commands that take a key file
//! name the scheme they run and check the file holds a key for it,
//! so a swapped file is caught rather than used.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use scytale::random::CtrDrbg;
use scytale::{Algorithm, Error, KeyInfo};
use zeroize::Zeroizing;

use crate::fail::{Result, usage};
use crate::{io, names};

/// Room for any PEM the library writes.
const PEM_ROOM: usize = 16 * 1024;

#[derive(Subcommand)]
pub enum KeyOp {
    /// Make a new private key, as PEM
    Generate(GenerateArgs),
    /// The public half of a private key, as PEM
    Public(PublicArgs),
    /// What a key file holds
    Show(ShowArgs),
}

impl KeyOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            KeyOp::Generate(a) => format!("generate {}", a.algorithm),
            KeyOp::Public(_) => "public".into(),
            KeyOp::Show(_) => "show".into(),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct GenerateArgs {
    /// The algorithm: ed25519, ecdsa-p256, rsa-3072, ml-kem-768, ...
    pub algorithm: String,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct PublicArgs {
    /// The private key file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct ShowArgs {
    /// The key file; standard input without one
    file: Option<PathBuf>,
}

/// Runs `$body` for each post-quantum signature set, with `$m` bound
/// to its module, for the `Algorithm` in `$alg`; `$else` otherwise.
macro_rules! with_pq_sig {
    ($alg:expr, $m:ident => $body:expr, _ => $else:expr) => {
        match $alg {
            scytale::Algorithm::MlDsa44 => {
                use scytale::sig::ml_dsa::ml_dsa_44 as $m;
                $body
            }
            scytale::Algorithm::MlDsa65 => {
                use scytale::sig::ml_dsa::ml_dsa_65 as $m;
                $body
            }
            scytale::Algorithm::MlDsa87 => {
                use scytale::sig::ml_dsa::ml_dsa_87 as $m;
                $body
            }
            scytale::Algorithm::SlhDsaSha2_128s => {
                use scytale::sig::slh_dsa::sha2_128s as $m;
                $body
            }
            scytale::Algorithm::SlhDsaSha2_128f => {
                use scytale::sig::slh_dsa::sha2_128f as $m;
                $body
            }
            scytale::Algorithm::SlhDsaSha2_192s => {
                use scytale::sig::slh_dsa::sha2_192s as $m;
                $body
            }
            scytale::Algorithm::SlhDsaSha2_192f => {
                use scytale::sig::slh_dsa::sha2_192f as $m;
                $body
            }
            scytale::Algorithm::SlhDsaSha2_256s => {
                use scytale::sig::slh_dsa::sha2_256s as $m;
                $body
            }
            scytale::Algorithm::SlhDsaSha2_256f => {
                use scytale::sig::slh_dsa::sha2_256f as $m;
                $body
            }
            scytale::Algorithm::SlhDsaShake128s => {
                use scytale::sig::slh_dsa::shake_128s as $m;
                $body
            }
            scytale::Algorithm::SlhDsaShake128f => {
                use scytale::sig::slh_dsa::shake_128f as $m;
                $body
            }
            scytale::Algorithm::SlhDsaShake192s => {
                use scytale::sig::slh_dsa::shake_192s as $m;
                $body
            }
            scytale::Algorithm::SlhDsaShake192f => {
                use scytale::sig::slh_dsa::shake_192f as $m;
                $body
            }
            scytale::Algorithm::SlhDsaShake256s => {
                use scytale::sig::slh_dsa::shake_256s as $m;
                $body
            }
            scytale::Algorithm::SlhDsaShake256f => {
                use scytale::sig::slh_dsa::shake_256f as $m;
                $body
            }
            _ => $else,
        }
    };
}

/// As [`with_pq_sig`] for the ML-KEM sets.
macro_rules! with_kem {
    ($alg:expr, $m:ident => $body:expr, _ => $else:expr) => {
        match $alg {
            scytale::Algorithm::MlKem512 => {
                use scytale::kem::ml_kem::ml_kem_512 as $m;
                $body
            }
            scytale::Algorithm::MlKem768 => {
                use scytale::kem::ml_kem::ml_kem_768 as $m;
                $body
            }
            scytale::Algorithm::MlKem1024 => {
                use scytale::kem::ml_kem::ml_kem_1024 as $m;
                $body
            }
            _ => $else,
        }
    };
}

pub(crate) use {with_kem, with_pq_sig};

/// The post-quantum algorithm a name stands for, `None` for any
/// other name.
pub fn pq_by_name(name: &str) -> Option<Algorithm> {
    Some(match name {
        "ml-kem-512" => Algorithm::MlKem512,
        "ml-kem-768" => Algorithm::MlKem768,
        "ml-kem-1024" => Algorithm::MlKem1024,
        "ml-dsa-44" => Algorithm::MlDsa44,
        "ml-dsa-65" => Algorithm::MlDsa65,
        "ml-dsa-87" => Algorithm::MlDsa87,
        "slh-dsa-sha2-128s" => Algorithm::SlhDsaSha2_128s,
        "slh-dsa-sha2-128f" => Algorithm::SlhDsaSha2_128f,
        "slh-dsa-sha2-192s" => Algorithm::SlhDsaSha2_192s,
        "slh-dsa-sha2-192f" => Algorithm::SlhDsaSha2_192f,
        "slh-dsa-sha2-256s" => Algorithm::SlhDsaSha2_256s,
        "slh-dsa-sha2-256f" => Algorithm::SlhDsaSha2_256f,
        "slh-dsa-shake-128s" => Algorithm::SlhDsaShake128s,
        "slh-dsa-shake-128f" => Algorithm::SlhDsaShake128f,
        "slh-dsa-shake-192s" => Algorithm::SlhDsaShake192s,
        "slh-dsa-shake-192f" => Algorithm::SlhDsaShake192f,
        "slh-dsa-shake-256s" => Algorithm::SlhDsaShake256s,
        "slh-dsa-shake-256f" => Algorithm::SlhDsaShake256f,
        _ => return None,
    })
}

/// What a file is called in a message.
fn shown(path: Option<&Path>) -> String {
    path.map_or("standard input".into(), |p| p.display().to_string())
}

/// A key file and what it holds.
pub fn read(path: Option<&Path>) -> Result<(Zeroizing<Vec<u8>>, KeyInfo)> {
    let pem = Zeroizing::new(io::read_all(path)?);
    let info = KeyInfo::try_from_pem(&pem).map_err(|e| {
        let why = match e {
            Error::InvalidEncoding => {
                if pem.is_empty() {
                    "it is empty"
                } else if !pem.starts_with(b"-----BEGIN ") {
                    "no PEM block (-----BEGIN ...-----) at its start; keys \
                     are PEM here, and DER is not read"
                } else {
                    "not a PRIVATE KEY, PUBLIC KEY, RSA or EC PRIVATE \
                     KEY block, or malformed inside"
                }
            }
            Error::NotSupported => {
                "a PEM block for an algorithm this tool does not have"
            }
            Error::UnsupportedVersion => {
                "a PKCS#8 version this tool does \
                                          not read"
            }
            _ => "not readable as a key",
        };
        usage!("{}: not a key file: {why}", shown(path))
    })?;
    Ok((pem, info))
}

/// The private key in `path`, holding one of `want`, for `scheme`.
pub fn read_private(
    path: &Path,
    want: &[Algorithm],
    scheme: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let (pem, info) = read(Some(path))?;
    fits(path, info, want, scheme)?;
    if !info.private {
        return Err(usage!(
            "{} holds the public half of a{} {} key; {scheme} needs the \
             private key here",
            path.display(),
            article(info.algorithm),
            info.algorithm
        ));
    }
    Ok(pem)
}

/// The public key in `path`, holding one of `want`, for `scheme`.
pub fn read_public(
    path: &Path,
    want: &[Algorithm],
    scheme: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let (pem, info) = read(Some(path))?;
    fits(path, info, want, scheme)?;
    if info.private {
        return Err(usage!(
            "{} holds a{} {} private key; {scheme} needs the public key \
             here, and scytale key public makes it",
            path.display(),
            article(info.algorithm),
            info.algorithm
        ));
    }
    Ok(pem)
}

/// Checks the key is for one of the algorithms `scheme` runs on.
fn fits(
    path: &Path,
    info: KeyInfo,
    want: &[Algorithm],
    scheme: &str,
) -> Result<()> {
    if want.contains(&info.algorithm) {
        return Ok(());
    }
    let names: Vec<&str> = want.iter().map(|a| a.name()).collect();
    Err(usage!(
        "{} holds a{} {} key; {scheme} needs {} key",
        path.display(),
        article(info.algorithm),
        info.algorithm,
        match names.as_slice() {
            [one] => format!("a{} {one}", article(want[0])),
            [rest @ .., last] => format!("a {} or {last}", rest.join(", ")),
            [] => unreachable!("a scheme runs on some key"),
        }
    ))
}

/// "n" before a name that starts with a vowel sound.
fn article(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Ed25519
        | Algorithm::X25519
        | Algorithm::Rsa
        | Algorithm::RsaPss
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024
        | Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87 => "n",
        _ => "",
    }
}

pub fn run(op: KeyOp) -> Result<()> {
    match op {
        KeyOp::Generate(args) => {
            let pem = generate(&args.algorithm)?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &pem, false)
        }
        KeyOp::Public(args) => {
            let (pem, info) = read(args.file.as_deref())?;
            if !info.private {
                return Err(usage!(
                    "{} already holds the public half of a{} {} key",
                    shown(args.file.as_deref()),
                    article(info.algorithm),
                    info.algorithm
                ));
            }
            let public = public(info.algorithm, &pem)?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, &public, false)
        }
        KeyOp::Show(args) => {
            let (pem, info) = read(args.file.as_deref())?;
            let half = if info.private { "private" } else { "public" };
            let detail = match (info.algorithm, info.private) {
                (Algorithm::Rsa | Algorithm::RsaPss, true) => {
                    let key =
                        scytale::sig::rsa::PrivateKey::try_from_pem(&pem)?;
                    format!(", {} bits", key.bits())
                }
                (Algorithm::Rsa | Algorithm::RsaPss, false) => {
                    let key = scytale::sig::rsa::PublicKey::try_from_pem(&pem)?;
                    format!(", {} bits", key.bits())
                }
                _ => String::new(),
            };
            println!("{} {half} key{detail}", info.algorithm);
            Ok(())
        }
    }
}

/// A fresh private key under `name`, as PEM.
fn generate(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut rng = CtrDrbg::from_system()?;
    let mut pem = Zeroizing::new(vec![0u8; PEM_ROOM]);
    macro_rules! into_pem {
        ($key:expr) => {{
            let n = $key.pem_bytes(&mut pem)?;
            pem.truncate(n);
            return Ok(pem);
        }};
    }
    // rsa-N takes any N, so the table is consulted for the rest.
    if let Some(bits) = name.strip_prefix("rsa-") {
        let bits: usize = bits.parse().map_err(|_| {
            usage!("rsa-{bits}: N in rsa-N is a bit count, 1024 to 8192")
        })?;
        if !(1024..=8192).contains(&bits) || !bits.is_multiple_of(8) {
            return Err(usage!(
                "rsa-{bits}: a modulus is 1024 to 8192 bits, a multiple \
                 of 8; 3072 is the size to reach for"
            ));
        }
        let key = scytale::sig::rsa::PrivateKey::generate(&mut rng, bits)?;
        into_pem!(key);
    }
    let name = names::KEY.find(name)?.name;
    match name {
        "ed25519" => {
            let key = scytale::sig::ed25519::PrivateKey::generate(&mut rng)?;
            Ok(Zeroizing::new(key.pem_bytes().to_vec()))
        }
        "x25519" => {
            let key = scytale::kex::x25519::PrivateKey::generate(&mut rng)?;
            Ok(Zeroizing::new(key.pem_bytes().to_vec()))
        }
        "ecdsa-p256" | "ecdh-p256" => {
            into_pem!(scytale::sig::ecdsa::p256::PrivateKey::generate(
                &mut rng
            )?)
        }
        "ecdsa-p384" | "ecdh-p384" => {
            into_pem!(scytale::sig::ecdsa::p384::PrivateKey::generate(
                &mut rng
            )?)
        }
        "ecdsa-p521" | "ecdh-p521" => {
            into_pem!(scytale::sig::ecdsa::p521::PrivateKey::generate(
                &mut rng
            )?)
        }
        _ => {
            let Some(algorithm) = pq_by_name(name) else {
                return Err(usage!("no key algorithm named \"{name}\""));
            };
            with_kem!(algorithm, m => {
                into_pem!(m::PrivateKey::generate(&mut rng)?)
            }, _ => with_pq_sig!(algorithm, m => {
                into_pem!(m::PrivateKey::generate(&mut rng)?)
            }, _ => Err(usage!("no key algorithm named \"{name}\""))))
        }
    }
}

/// The public half of the private key in `pem`, as PEM.
fn public(algorithm: Algorithm, pem: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; PEM_ROOM];
    macro_rules! into_pem {
        ($public:expr) => {{
            let n = $public.pem_bytes(&mut out)?;
            out.truncate(n);
            return Ok(out);
        }};
    }
    match algorithm {
        Algorithm::Ed25519 => {
            let key = scytale::sig::ed25519::PrivateKey::try_from_pem(pem)?;
            Ok(key.public_key().pem_bytes().to_vec())
        }
        Algorithm::X25519 => {
            let key = scytale::kex::x25519::PrivateKey::try_from_pem(pem)?;
            Ok(key.public_key().pem_bytes().to_vec())
        }
        Algorithm::P256 => {
            let key = scytale::sig::ecdsa::p256::PrivateKey::try_from_pem(pem)?;
            into_pem!(key.public_key())
        }
        Algorithm::P384 => {
            let key = scytale::sig::ecdsa::p384::PrivateKey::try_from_pem(pem)?;
            into_pem!(key.public_key())
        }
        Algorithm::P521 => {
            let key = scytale::sig::ecdsa::p521::PrivateKey::try_from_pem(pem)?;
            into_pem!(key.public_key())
        }
        Algorithm::Rsa | Algorithm::RsaPss => {
            let key = scytale::sig::rsa::PrivateKey::try_from_pem(pem)?;
            into_pem!(key.public_key())
        }
        other => with_kem!(other, m => {
            into_pem!(m::PrivateKey::try_from_pem(pem)?.public_key())
        }, _ => with_pq_sig!(other, m => {
            into_pem!(m::PrivateKey::try_from_pem(pem)?.public_key())
        }, _ => Err(usage!("{other}: no public half is defined")))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name in the table generates a key, but for the RSA
    /// sizes, which are slow and share one path.
    #[test]
    fn table_matches_dispatch() {
        for entry in names::KEY.iter() {
            if entry.name.starts_with("rsa-") {
                continue;
            }
            let pem = generate(entry.name).unwrap();
            let info = KeyInfo::try_from_pem(&pem).unwrap();
            assert!(info.private, "{}", entry.name);
            let public = public(info.algorithm, &pem).unwrap();
            assert!(!KeyInfo::try_from_pem(&public).unwrap().private);
        }
    }
}
