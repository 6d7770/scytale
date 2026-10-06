//! ECDSA keyGen, keyVer, sigGen, sigVer and the deterministic
//! sigGen, for the P-256, P-384 and P-521 groups: the P-224 and
//! binary-curve groups are not implemented, and the SHAKE groups are
//! skipped since ECDSA over an XOF is not offered.
//!
//! The deterministic suite is the exact check on signing, since
//! RFC 6979 fixes the nonce. The random-nonce sigGen suite cannot be
//! reproduced, so its answers are verified instead, which still
//! checks the public key against `d` and the arithmetic against a
//! signature NIST made. Both suites also carry SP 800-106 groups,
//! whose message is randomized with a value the file supplies before
//! hashing; that scheme is not offered, so those groups are skipped.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{hex, load};
use crate::BlockType;
use crate::Error;
use crate::hash::Hash;
use crate::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
};
use crate::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use crate::sig::ecdsa::{p256, p384, p521};
use serde_json::Value;

/// One curve's key types, so a driver can be written once.
pub trait Curve {
    const NAME: &'static str;
    const WIDTH: usize;
    type Private;
    type Public;
    fn private(d: &[u8]) -> Result<Self::Private, Error>;
    fn public(sec1: &[u8]) -> Result<Self::Public, Error>;
    fn public_of(key: &Self::Private) -> Vec<u8>;
    fn sign<H: Hash + Clone + BlockType + Default>(
        key: &Self::Private,
        message: &[u8],
    ) -> Vec<u8>;
    fn verify<H: Hash + Clone + BlockType + Default>(
        key: &Self::Public,
        message: &[u8],
        sig: &[u8],
    ) -> bool;
}

macro_rules! curve {
    ($name:ident, $module:ident, $acvp:literal, $width:literal) => {
        pub struct $name;
        impl Curve for $name {
            const NAME: &'static str = $acvp;
            const WIDTH: usize = $width;
            type Private = $module::PrivateKey;
            type Public = $module::PublicKey;
            fn private(d: &[u8]) -> Result<Self::Private, Error> {
                let d: [u8; $width] = d.try_into().expect("d width");
                $module::PrivateKey::try_new(&d)
            }
            fn public(sec1: &[u8]) -> Result<Self::Public, Error> {
                $module::PublicKey::try_from_sec1(sec1)
            }
            fn public_of(key: &Self::Private) -> Vec<u8> {
                key.public_key().sec1_bytes().to_vec()
            }
            fn sign<H: Hash + Clone + BlockType + Default>(
                key: &Self::Private,
                message: &[u8],
            ) -> Vec<u8> {
                key.sign::<H>(message).expect("sign").to_vec()
            }
            fn verify<H: Hash + Clone + BlockType + Default>(
                key: &Self::Public,
                message: &[u8],
                sig: &[u8],
            ) -> bool {
                match <[u8; 2 * $width]>::try_from(sig) {
                    Ok(sig) => key.verify::<H>(message, &sig).is_ok(),
                    Err(_) => false,
                }
            }
        }
    };
}

curve!(P256, p256, "P-256", 32);
curve!(P384, p384, "P-384", 48);
curve!(P521, p521, "P-521", 66);

/// A big-endian value left-padded to `width`, or `None` when it is
/// wider, which a keyVer case may deliberately be.
fn padded(v: &Value, width: usize) -> Option<Vec<u8>> {
    let bytes = hex(v);
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let value = &bytes[start..];
    if value.len() > width {
        return None;
    }
    let mut out = vec![0u8; width - value.len()];
    out.extend_from_slice(value);
    Some(out)
}

/// The uncompressed point from a group's or case's `qx` and `qy`.
fn sec1(v: &Value, width: usize) -> Option<Vec<u8>> {
    let mut out = vec![0x04];
    out.extend(padded(&v["qx"], width)?);
    out.extend(padded(&v["qy"], width)?);
    Some(out)
}

/// The signature `r || s` from a case.
fn signature(t: &Value, width: usize) -> Option<Vec<u8>> {
    let mut out = padded(&t["r"], width)?;
    out.extend(padded(&t["s"], width)?);
    Some(out)
}

/// Calls `$f::<C, H>($args)` for the group's hash, or skips the
/// group for a hash the scheme does not take here.
macro_rules! with_hash {
    ($hash:expr, $f:ident::<$c:ty>($($arg:expr),*)) => {
        match $hash {
            "SHA2-224" => Some($f::<$c, Sha224>($($arg),*)),
            "SHA2-256" => Some($f::<$c, Sha256>($($arg),*)),
            "SHA2-384" => Some($f::<$c, Sha384>($($arg),*)),
            "SHA2-512" => Some($f::<$c, Sha512>($($arg),*)),
            "SHA2-512/224" => Some($f::<$c, Sha512_224>($($arg),*)),
            "SHA2-512/256" => Some($f::<$c, Sha512_256>($($arg),*)),
            "SHA3-224" => Some($f::<$c, Sha3_224>($($arg),*)),
            "SHA3-256" => Some($f::<$c, Sha3_256>($($arg),*)),
            "SHA3-384" => Some($f::<$c, Sha3_384>($($arg),*)),
            "SHA3-512" => Some($f::<$c, Sha3_512>($($arg),*)),
            "SHAKE-128" | "SHAKE-256" => None,
            other => panic!("unknown hash {other}"),
        }
    };
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors.
pub fn run_key_gen() {
    let file = "ECDSA-KeyGen-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            match group["curve"].as_str() {
                Some(P256::NAME) => key_gen::<P256>(t, &tag),
                Some(P384::NAME) => key_gen::<P384>(t, &tag),
                Some(P521::NAME) => key_gen::<P521>(t, &tag),
                _ => continue,
            }
            cases += 1;
        }
    }
    assert!(cases >= 18, "only {cases} keyGen cases");
}

fn key_gen<C: Curve>(t: &Value, tag: &str) {
    let d = padded(&t["d"], C::WIDTH).expect("d");
    let key = C::private(&d).expect("private key");
    assert_eq!(C::public_of(&key), sec1(t, C::WIDTH).expect("q"), "{tag}");
}

/// Runs the key verification suite; a no-op without the vendored
/// vectors.
pub fn run_key_ver() {
    let file = "ECDSA-KeyVer-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let accepted = match group["curve"].as_str() {
                Some(P256::NAME) => key_ver::<P256>(t),
                Some(P384::NAME) => key_ver::<P384>(t),
                Some(P521::NAME) => key_ver::<P521>(t),
                _ => continue,
            };
            let should_pass = t["testPassed"].as_bool().expect("testPassed");
            assert_eq!(accepted, should_pass, "{tag}: {}", t["reason"]);
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 9, "only {cases} keyVer cases");
    assert!(rejections >= 4, "only {rejections} rejections");
}

fn key_ver<C: Curve>(t: &Value) -> bool {
    // A coordinate wider than the field cannot be presented at all.
    sec1(t, C::WIDTH).is_some_and(|q| C::public(&q).is_ok())
}

/// Runs the signature verification suite; a no-op without the
/// vendored vectors.
pub fn run_sig_ver() {
    let file = "ECDSA-SigVer-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let hash = group["hashAlg"].as_str().expect("hashAlg");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let accepted = match group["curve"].as_str() {
                Some(P256::NAME) => with_hash!(hash, sig_ver::<P256>(t)),
                Some(P384::NAME) => with_hash!(hash, sig_ver::<P384>(t)),
                Some(P521::NAME) => with_hash!(hash, sig_ver::<P521>(t)),
                _ => continue,
            };
            let Some(accepted) = accepted else {
                continue;
            };
            let should_pass = t["testPassed"].as_bool().expect("testPassed");
            assert_eq!(accepted, should_pass, "{tag}: {}", t["reason"]);
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 105, "only {cases} sigVer cases");
    assert!(rejections >= 40, "only {rejections} rejections");
}

fn sig_ver<C: Curve, H: Hash + Clone + BlockType + Default>(t: &Value) -> bool {
    let Some(q) = sec1(t, C::WIDTH) else {
        return false;
    };
    let Ok(key) = C::public(&q) else {
        return false;
    };
    match signature(t, C::WIDTH) {
        Some(sig) => C::verify::<H>(&key, &hex(&t["message"]), &sig),
        None => false,
    }
}

/// Runs the random-nonce generation suite by verifying its
/// answers; a no-op without the vendored vectors.
pub fn run_sig_gen() {
    let file = "ECDSA-SigGen-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "ECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["conformance"] == "SP800-106" {
            continue;
        }
        let hash = group["hashAlg"].as_str().expect("hashAlg");
        let ran = match group["curve"].as_str() {
            Some(P256::NAME) => with_hash!(hash, sig_gen::<P256>(group, false)),
            Some(P384::NAME) => with_hash!(hash, sig_gen::<P384>(group, false)),
            Some(P521::NAME) => with_hash!(hash, sig_gen::<P521>(group, false)),
            _ => continue,
        };
        cases += ran.unwrap_or(0);
    }
    assert!(cases >= 300, "only {cases} sigGen cases");
}

/// Runs the deterministic generation suite, comparing exact
/// signatures; a no-op without the vendored vectors.
pub fn run_det_sig_gen() {
    let file = "DetECDSA-SigGen-FIPS186-5/internalProjection.json";
    let Some(doc) = load(file, "DetECDSA", "FIPS186-5") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["conformance"] == "SP800-106" {
            continue;
        }
        let hash = group["hashAlg"].as_str().expect("hashAlg");
        let ran = match group["curve"].as_str() {
            Some(P256::NAME) => with_hash!(hash, sig_gen::<P256>(group, true)),
            Some(P384::NAME) => with_hash!(hash, sig_gen::<P384>(group, true)),
            Some(P521::NAME) => with_hash!(hash, sig_gen::<P521>(group, true)),
            _ => continue,
        };
        cases += ran.unwrap_or(0);
    }
    assert!(cases >= 330, "only {cases} deterministic sigGen cases");
}

/// One sigGen group: the key from `d` must give the group's `q`,
/// and each case's signature must verify; when `exact`, it must be
/// the one this crate makes. Returns the cases run.
fn sig_gen<C: Curve, H: Hash + Clone + BlockType + Default>(
    group: &Value,
    exact: bool,
) -> usize {
    let d = padded(&group["d"], C::WIDTH).expect("d");
    let key = C::private(&d).expect("private key");
    let q = sec1(group, C::WIDTH).expect("q");
    assert_eq!(C::public_of(&key), q, "tgId {}", group["tgId"]);
    let public = C::public(&q).expect("public key");
    let mut cases = 0;
    for t in group["tests"].as_array().expect("tests") {
        let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
        let message = hex(&t["message"]);
        let sig = signature(t, C::WIDTH).expect("signature");
        if exact {
            assert_eq!(C::sign::<H>(&key, &message), sig, "{tag}");
        }
        assert!(C::verify::<H>(&public, &message, &sig), "{tag}");
        cases += 1;
    }
    cases
}
