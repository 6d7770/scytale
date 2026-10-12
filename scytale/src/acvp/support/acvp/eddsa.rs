//! EDDSA keyGen, keyVer, sigGen and sigVer, for the Ed25519 groups:
//! plain Ed25519, and Ed25519ph where a group is marked `preHash`.
//! The pre-hashed cases give the message, which the harness hashes
//! with SHA-512 before handing the digest over. Signing is
//! deterministic, so sigGen compares exact bytes; sigVer and keyVer
//! carry the deliberately damaged cases. The vendored files have no
//! Ed25519ctx case: every group without pre-hashing has an empty
//! context, which is plain Ed25519.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{hex, load};
use crate::Error;
use crate::hash::Hash;
use crate::hash::sha2::Sha512;
use crate::sig::ed25519;

/// A signature over `message` under `context`, by whichever variant
/// the group names.
fn sign(
    secret: &[u8; 32],
    prehash: bool,
    context: &[u8],
    message: &[u8],
) -> [u8; 64] {
    if prehash {
        let digest = Sha512::digest(message);
        ed25519::sign_ph_deterministic(secret, context, &digest)
            .expect("sign_ph")
    } else {
        assert!(context.is_empty(), "no Ed25519ctx case is expected");
        ed25519::sign_deterministic(secret, message)
    }
}

/// Whether `signature` verifies, by whichever variant the group
/// names.
fn verify(
    public: &[u8; 32],
    prehash: bool,
    context: &[u8],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Error> {
    if prehash {
        let digest = Sha512::digest(message);
        ed25519::verify_ph(public, context, &digest, signature)
    } else {
        assert!(context.is_empty(), "no Ed25519ctx case is expected");
        ed25519::verify(public, message, signature)
    }
}

/// Runs the generation suite; a no-op without the vendored vectors.
pub fn run_sig_gen() {
    let file = "EDDSA-SigGen-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    let mut cases = 0;
    let mut prehashed = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" {
            continue;
        }
        let prehash = group["preHash"].as_bool().expect("preHash");
        let secret: [u8; 32] = hex(&group["d"]).try_into().expect("d");
        let public: [u8; 32] = hex(&group["q"]).try_into().expect("q");
        assert_eq!(ed25519::public_key(&secret), public);
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let message = hex(&t["message"]);
            let context = hex(&t["context"]);
            let length = t["contextLength"].as_u64().expect("contextLength");
            assert_eq!(context.len() as u64, length, "{tag}");
            let signature = sign(&secret, prehash, &context, &message);
            assert_eq!(signature[..], hex(&t["signature"])[..], "{tag}");
            verify(&public, prehash, &context, &message, &signature)
                .expect("verify");
            cases += 1;
            if prehash {
                prehashed += 1;
            }
        }
    }
    assert!(cases >= 80, "only {cases} sigGen cases");
    assert!(prehashed >= 40, "only {prehashed} Ed25519ph sigGen cases");
}

/// Runs the verification suite; a no-op without the vendored
/// vectors.
pub fn run_sig_ver() {
    let file = "EDDSA-SigVer-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    let mut cases = 0;
    let mut rejections = 0;
    let mut prehashed = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" {
            continue;
        }
        let prehash = group["preHash"].as_bool().expect("preHash");
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let should_pass = t["testPassed"].as_bool().expect("testPassed");
            let public: [u8; 32] = hex(&t["q"]).try_into().expect("q");
            let message = hex(&t["message"]);
            // The verification cases carry no context field; an absent
            // one is the empty context.
            let context = if t["context"].is_null() {
                Vec::new()
            } else {
                hex(&t["context"])
            };
            let signature: [u8; 64] =
                hex(&t["signature"]).try_into().expect("signature");
            let accepted =
                verify(&public, prehash, &context, &message, &signature)
                    .is_ok();
            if prehash {
                prehashed += 1;
            }
            assert_eq!(accepted, should_pass, "{tag}");
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 10, "only {cases} sigVer cases");
    assert!(prehashed >= 5, "only {prehashed} Ed25519ph sigVer cases");
    assert!(rejections >= 1, "no case had to be rejected");
}

/// Runs the key generation suite; a no-op without the vendored
/// vectors. Ed448 is not implemented, so those groups are skipped.
pub fn run_key_gen() {
    let file = "EDDSA-KeyGen-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "keyGen");
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" {
            eprintln!(
                "tgId {}: {} not implemented; skipping",
                group["tgId"], group["curve"]
            );
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let secret: [u8; 32] = hex(&t["d"]).try_into().expect("d");
            let public: [u8; 32] = hex(&t["q"]).try_into().expect("q");
            assert_eq!(ed25519::public_key(&secret), public, "{tag}");
            cases += 1;
        }
    }
    assert!(cases >= 3, "only {cases} keyGen cases");
}

/// Runs the key validation suite; a no-op without the vendored
/// vectors.
///
/// The crate has no standalone key check: a public key is validated
/// as part of verifying with it. That is enough here because
/// [`ed25519::verify`] documents the distinction these cases turn on,
/// returning `InvalidPublicKey` when the key is not a point on the
/// curve and `InvalidSignature` for everything else. The signature
/// handed in is therefore a dummy, and the verdict is read from the
/// error alone.
pub fn run_key_ver() {
    let file = "EDDSA-KeyVer-1.0/internalProjection.json";
    let Some(doc) = load(file, "EDDSA", "1.0") else {
        return;
    };
    assert_eq!(doc["mode"], "keyVer");
    let mut cases = 0;
    let mut rejections = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["curve"] != "ED-25519" {
            eprintln!(
                "tgId {}: {} not implemented; skipping",
                group["tgId"], group["curve"]
            );
            continue;
        }
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            let should_pass = t["testPassed"].as_bool().expect("testPassed");
            let public: [u8; 32] = hex(&t["q"]).try_into().expect("q");
            let usable = !matches!(
                ed25519::verify(&public, b"", &[0u8; 64]),
                Err(Error::InvalidPublicKey)
            );
            assert_eq!(usable, should_pass, "{tag}");
            cases += 1;
            if !should_pass {
                rejections += 1;
            }
        }
    }
    assert!(cases >= 4, "only {cases} keyVer cases");
    assert!(rejections >= 2, "only {rejections} rejections");
}
