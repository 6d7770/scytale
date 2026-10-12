//! `scytale pke`: encryption to a public key. RSA-OAEP takes a short
//! message; HPKE (RFC 9180, base mode) takes one of any length.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use scytale::aead::{ChaCha20Poly1305, Gcm};
use scytale::cipher::aes::{Aes128, Aes256};
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::kex::{ecdh, x25519};
use scytale::pke::hpke::{self, Cipher, Context, Kdf, TAG_SIZE};
use scytale::pke::rsa;
use scytale::random::CtrDrbg;
use scytale::{Algorithm, Key};
use zeroize::Zeroizing;

use crate::fail::{Result, usage, verify};
use crate::hash::with_hash;
use crate::{io, key, names, value};

#[derive(Subcommand)]
pub enum PkeOp {
    /// Encrypt the input to a public key
    Encrypt(EncryptArgs),
    /// Decrypt the input with the private key
    Decrypt(DecryptArgs),
}

impl PkeOp {
    /// The words a message about this call starts with.
    pub fn context(&self) -> String {
        match self {
            PkeOp::Encrypt(a) => format!("encrypt {}", a.scheme),
            PkeOp::Decrypt(a) => format!("decrypt {}", a.scheme),
        }
    }
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct EncryptArgs {
    /// The scheme: rsa-oaep-sha256, hpke-x25519-sha256-aes-128-gcm, ...
    pub scheme: String,
    /// The public key file (PEM)
    #[arg(short, long)]
    public: PathBuf,
    /// The OAEP label (str: allowed); empty without it
    #[arg(long)]
    label: Option<String>,
    /// HPKE's info, binding the message to a context (str: allowed);
    /// empty without it
    #[arg(long)]
    info: Option<String>,
    /// HPKE's additional data (str: allowed); empty without it
    #[arg(long)]
    aad: Option<String>,
    /// The message file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file rather than standard output
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = crate::help::VALUES)]
pub struct DecryptArgs {
    /// The scheme: rsa-oaep-sha256, hpke-x25519-sha256-aes-128-gcm, ...
    pub scheme: String,
    /// The private key file (PEM)
    #[arg(short, long)]
    key: PathBuf,
    /// The OAEP label (str: allowed); empty without it
    #[arg(long)]
    label: Option<String>,
    /// HPKE's info, as the message was sealed with (str: allowed)
    #[arg(long)]
    info: Option<String>,
    /// HPKE's additional data, as the message was sealed with
    #[arg(long)]
    aad: Option<String>,
    /// The ciphertext file; standard input without one
    file: Option<PathBuf>,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

/// The hash a scheme name carries.
fn hash_of(scheme: &str) -> Result<(&'static str, &'static str)> {
    let name = names::PKE.find(scheme)?.name;
    let hash = name
        .strip_prefix("rsa-oaep-")
        .ok_or_else(|| usage!("no encryption scheme named \"{name}\""))?;
    Ok((name, hash))
}

pub fn run(op: PkeOp) -> Result<()> {
    let scheme = match &op {
        PkeOp::Encrypt(a) => &a.scheme,
        PkeOp::Decrypt(a) => &a.scheme,
    };
    let name = names::PKE.find(scheme)?.name;
    if let Some(suite) = name.strip_prefix("hpke-") {
        return run_hpke(op, name, suite);
    }
    let (info, aad) = match &op {
        PkeOp::Encrypt(a) => (&a.info, &a.aad),
        PkeOp::Decrypt(a) => (&a.info, &a.aad),
    };
    if info.is_some() || aad.is_some() {
        return Err(usage!(
            "{name} takes no --info or --aad; those are HPKE's, and \
             RSA-OAEP's one input of the kind is --label"
        ));
    }
    match op {
        PkeOp::Encrypt(args) => {
            let (name, hash) = hash_of(&args.scheme)?;
            let pem = key::read_public(&args.public, &[Algorithm::Rsa], name)?;
            let public = rsa::PublicKey::try_from_pem(&pem)?;
            let label = value::text(args.label.as_deref(), "--label")?;
            let message = Zeroizing::new(io::read_all(args.file.as_deref())?);
            let mut rng = CtrDrbg::from_system()?;
            let digest = names::digest_len(hash).unwrap_or(0);
            let most = public.modulus_len().saturating_sub(2 * digest + 2);
            if message.len() > most {
                return Err(usage!(
                    "the message is {} bytes; {name} under this {}-bit key \
                     takes at most {most}: encrypt a key with it, and the \
                     message with the key",
                    message.len(),
                    public.bits()
                ));
            }
            let ciphertext = with_hash!(hash, H => {
                Ok(public.encrypt_oaep::<H, _>(&mut rng, &label, &message)?)
            })?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, ciphertext.as_ref(), false)
        }
        PkeOp::Decrypt(args) => {
            let (name, hash) = hash_of(&args.scheme)?;
            let pem = key::read_private(&args.key, &[Algorithm::Rsa], name)?;
            let private = rsa::PrivateKey::try_from_pem(&pem)?;
            let label = value::text(args.label.as_deref(), "--label")?;
            let ciphertext = io::read_all(args.file.as_deref())?;
            if ciphertext.len() != private.modulus_len() {
                return Err(usage!(
                    "the ciphertext is {} bytes; under this {}-bit key it \
                     is {}",
                    ciphertext.len(),
                    private.bits(),
                    private.modulus_len()
                ));
            }
            let mut message = Zeroizing::new(vec![0u8; private.modulus_len()]);
            let n = with_hash!(hash, H => {
                let n = private
                    .decrypt_oaep::<H>(&label, &ciphertext, &mut message)?;
                Ok(n)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &message[..n], false)
        }
    }
}

/// An HPKE suite, from the part of its name after `hpke-`: the KEM, as
/// the key type is named, then the KDF's hash, then the AEAD.
fn hpke_parts(suite: &str) -> Option<(&str, &str, &str)> {
    let kem = ["x25519", "ecdh-p256", "ecdh-p384", "ecdh-p521"]
        .into_iter()
        .find(|k| suite.starts_with(&format!("{k}-")))?;
    let rest = &suite[kem.len() + 1..];
    let (kdf, aead) = rest.split_once('-')?;
    Some((kem, kdf, aead))
}

/// The key type each KEM takes.
fn kem_key(kem: &str) -> Option<Algorithm> {
    Some(match kem {
        "x25519" => Algorithm::X25519,
        "ecdh-p256" => Algorithm::P256,
        "ecdh-p384" => Algorithm::P384,
        "ecdh-p521" => Algorithm::P521,
        _ => return None,
    })
}

/// Runs `$body` with `$h` the KDF's hash and `$a` the AEAD a suite
/// names; a name the table holds always matches.
macro_rules! with_suite {
    ($kdf:expr, $aead:expr, $h:ident, $a:ident => $body:expr) => {
        match ($kdf, $aead) {
            ("sha256", "aes-128-gcm") => {
                with_suite!(@ Sha256, Gcm<Aes128>, $h, $a, $body)
            }
            ("sha256", "aes-256-gcm") => {
                with_suite!(@ Sha256, Gcm<Aes256>, $h, $a, $body)
            }
            ("sha256", "chacha20-poly1305") => {
                with_suite!(@ Sha256, ChaCha20Poly1305, $h, $a, $body)
            }
            ("sha384", "aes-128-gcm") => {
                with_suite!(@ Sha384, Gcm<Aes128>, $h, $a, $body)
            }
            ("sha384", "aes-256-gcm") => {
                with_suite!(@ Sha384, Gcm<Aes256>, $h, $a, $body)
            }
            ("sha384", "chacha20-poly1305") => {
                with_suite!(@ Sha384, ChaCha20Poly1305, $h, $a, $body)
            }
            ("sha512", "aes-128-gcm") => {
                with_suite!(@ Sha512, Gcm<Aes128>, $h, $a, $body)
            }
            ("sha512", "aes-256-gcm") => {
                with_suite!(@ Sha512, Gcm<Aes256>, $h, $a, $body)
            }
            ("sha512", "chacha20-poly1305") => {
                with_suite!(@ Sha512, ChaCha20Poly1305, $h, $a, $body)
            }
            (kdf, aead) => Err(usage!("no HPKE suite with {kdf} and {aead}")),
        }
    };
    (@ $hty:ty, $aty:ty, $h:ident, $a:ident, $body:expr) => {{
        type $h = $hty;
        type $a = $aty;
        $body
    }};
}

/// The sender's side: `enc`, and the context to seal with, for the
/// public key in `pem`.
fn sender<H: Kdf, A: Cipher>(
    algorithm: Algorithm,
    pem: &[u8],
    rng: &mut CtrDrbg,
    info: &[u8],
) -> Result<(Vec<u8>, Context<H, A>)> {
    Ok(match algorithm {
        Algorithm::X25519 => {
            let public = x25519::PublicKey::try_from_pem(pem)?;
            let public = hpke::x25519::PublicKey::new(&public.bytes());
            let (enc, context) = public.sender(rng, info)?;
            (enc.to_vec(), context)
        }
        Algorithm::P256 => {
            let public = ecdh::p256::PublicKey::try_from_pem(pem)?;
            let public = hpke::p256::PublicKey::try_new(&public.sec1_bytes())?;
            let (enc, context) = public.sender(rng, info)?;
            (enc.to_vec(), context)
        }
        Algorithm::P384 => {
            let public = ecdh::p384::PublicKey::try_from_pem(pem)?;
            let public = hpke::p384::PublicKey::try_new(&public.sec1_bytes())?;
            let (enc, context) = public.sender(rng, info)?;
            (enc.to_vec(), context)
        }
        _ => {
            let public = ecdh::p521::PublicKey::try_from_pem(pem)?;
            let public = hpke::p521::PublicKey::try_new(&public.sec1_bytes())?;
            let (enc, context) = public.sender(rng, info)?;
            (enc.to_vec(), context)
        }
    })
}

/// The length of `enc` under a KEM.
fn enc_len(algorithm: Algorithm) -> usize {
    match algorithm {
        Algorithm::X25519 => hpke::x25519::ENCAPSULATED_SIZE,
        Algorithm::P256 => hpke::p256::ENCAPSULATED_SIZE,
        Algorithm::P384 => hpke::p384::ENCAPSULATED_SIZE,
        _ => hpke::p521::ENCAPSULATED_SIZE,
    }
}

/// The recipient's side: the context `enc` sets up under the private
/// key in `pem`. The outer error is the key's; the inner one is the
/// encapsulation's, which says only that the message is not ours.
fn recipient<H: Kdf, A: Cipher>(
    algorithm: Algorithm,
    pem: &[u8],
    enc: &[u8],
    info: &[u8],
) -> Result<std::result::Result<Context<H, A>, scytale::Error>> {
    let bad = scytale::Error::InvalidPublicKey;
    Ok(match algorithm {
        Algorithm::X25519 => {
            let private = x25519::PrivateKey::try_from_pem(pem)?;
            let secret = Key::from(private.secret_bytes());
            let private = hpke::x25519::PrivateKey::new(&secret);
            enc.try_into()
                .map_err(|_| bad)
                .and_then(|enc| private.recipient(enc, info))
        }
        Algorithm::P256 => {
            let private = ecdh::p256::PrivateKey::try_from_pem(pem)?;
            let secret = private.secret_bytes();
            let private = hpke::p256::PrivateKey::try_new(&secret)?;
            enc.try_into()
                .map_err(|_| bad)
                .and_then(|enc| private.recipient(enc, info))
        }
        Algorithm::P384 => {
            let private = ecdh::p384::PrivateKey::try_from_pem(pem)?;
            let secret = private.secret_bytes();
            let private = hpke::p384::PrivateKey::try_new(&secret)?;
            enc.try_into()
                .map_err(|_| bad)
                .and_then(|enc| private.recipient(enc, info))
        }
        _ => {
            let private = ecdh::p521::PrivateKey::try_from_pem(pem)?;
            let secret = private.secret_bytes();
            let private = hpke::p521::PrivateKey::try_new(&secret)?;
            enc.try_into()
                .map_err(|_| bad)
                .and_then(|enc| private.recipient(enc, info))
        }
    })
}

/// Seals `message` in place under a context and returns `enc`, the
/// ciphertext and the tag, in that order.
fn seal<H: Kdf, A: Cipher>(
    (enc, mut context): (Vec<u8>, Context<H, A>),
    aad: &[u8],
    mut message: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut tag = [0u8; TAG_SIZE];
    context.encrypt(aad, &mut message, &mut tag)?;
    let mut out = enc;
    out.extend_from_slice(&message);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens what [`seal`] made, the part after `enc`, under a context.
fn open<H: Kdf, A: Cipher>(
    context: std::result::Result<Context<H, A>, scytale::Error>,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // A bad encapsulation and a bad tag say the same thing: this was
    // not sealed to this key with this info.
    let not_ours = || verify!("the message does not decrypt");
    let mut context = context.map_err(|_| not_ours())?;
    let text_len = sealed.len().checked_sub(TAG_SIZE).ok_or_else(not_ours)?;
    let mut message = Zeroizing::new(sealed[..text_len].to_vec());
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&sealed[text_len..]);
    context
        .decrypt(aad, &mut message, &tag)
        .map_err(|_| not_ours())?;
    Ok(message)
}

fn run_hpke(op: PkeOp, name: &str, suite: &str) -> Result<()> {
    let (kem, kdf, aead) = hpke_parts(suite)
        .ok_or_else(|| usage!("no encryption scheme named \"{name}\""))?;
    let algorithm =
        kem_key(kem).ok_or_else(|| usage!("no HPKE KEM named \"{kem}\""))?;
    let label = match &op {
        PkeOp::Encrypt(a) => &a.label,
        PkeOp::Decrypt(a) => &a.label,
    };
    if label.is_some() {
        return Err(usage!("{name} takes --info and --aad, not --label"));
    }
    match op {
        PkeOp::Encrypt(args) => {
            let pem = key::read_public(&args.public, &[algorithm], name)?;
            let info = value::text(args.info.as_deref(), "--info")?;
            let aad = value::text(args.aad.as_deref(), "--aad")?;
            let message = Zeroizing::new(io::read_all(args.file.as_deref())?);
            let mut rng = CtrDrbg::from_system()?;
            let sealed = with_suite!(kdf, aead, H, A => {
                let sent = sender::<H, A>(algorithm, &pem, &mut rng, &info)?;
                seal(sent, &aad, message)
            })?;
            let mut out = io::output(args.out.as_deref(), false)?;
            io::write(&mut *out, &sealed, false)
        }
        PkeOp::Decrypt(args) => {
            let pem = key::read_private(&args.key, &[algorithm], name)?;
            let info = value::text(args.info.as_deref(), "--info")?;
            let aad = value::text(args.aad.as_deref(), "--aad")?;
            let input = io::read_all(args.file.as_deref())?;
            let least = enc_len(algorithm) + TAG_SIZE;
            if input.len() < least {
                return Err(verify!(
                    "the message is {} bytes; under {name} it is at least \
                     {least}",
                    input.len()
                ));
            }
            let (enc, sealed) = input.split_at(enc_len(algorithm));
            let message = with_suite!(kdf, aead, H, A => {
                let context = recipient::<H, A>(algorithm, &pem, enc, &info)?;
                open(context, &aad, sealed)
            })?;
            let mut out = io::output(args.out.as_deref(), true)?;
            io::write(&mut *out, &message, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name in the table parses into a KEM with a key type, a
    /// KDF and an AEAD the dispatch knows.
    #[test]
    fn table_matches_dispatch() {
        for entry in names::PKE.iter() {
            if let Some(suite) = entry.name.strip_prefix("hpke-") {
                let (kem, kdf, aead) = hpke_parts(suite).unwrap();
                assert!(kem_key(kem).is_some(), "{}", entry.name);
                // The name's KDF and AEAD are the identifiers RFC 9180
                // gives the types they dispatch to.
                let ids: Result<(u16, u16)> = with_suite!(kdf, aead, H, A => {
                    Ok((H::kdf_id(), A::aead_id()))
                });
                let want = (
                    match kdf {
                        "sha256" => 1,
                        "sha384" => 2,
                        _ => 3,
                    },
                    match aead {
                        "aes-128-gcm" => 1,
                        "aes-256-gcm" => 2,
                        _ => 3,
                    },
                );
                assert_eq!(ids.unwrap(), want, "{}", entry.name);
            } else {
                assert!(hash_of(entry.name).is_ok(), "{}", entry.name);
            }
        }
    }
}
