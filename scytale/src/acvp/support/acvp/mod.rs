//! Drivers for NIST ACVP vector files, generic over the primitive's
//! trait so any implementation can run them.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

pub mod aes_cbc;
pub mod aes_ccm;
pub mod aes_cfb1;
pub mod aes_cfb128;
pub mod aes_cfb8;
pub mod aes_ctr;
pub mod aes_ecb;
pub mod aes_ff1;
pub mod aes_ff3_1;
pub mod aes_gcm;
pub mod aes_gcm_siv;
pub mod aes_gmac;
pub mod aes_kw;
pub mod aes_kwp;
pub mod aes_ofb;
pub mod aes_xpn;
pub mod aes_xts;
pub mod cmac_aes;
pub mod cshake;
pub mod ctr_drbg;
pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod kda_hkdf;
pub mod kmac;
pub mod kts_ifc;
pub mod ml_dsa;
pub mod ml_kem;
pub mod pbkdf;
pub mod rsa_primitive;
pub mod rsa_sig;
pub mod sha;
pub mod shake;
pub mod slh_dsa;
pub mod tls12_kdf;
pub mod xecdh;

use crate::KeyType;
use crate::cipher::BlockCipher;
use serde_json::Value;

pub fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Loads and parses a vector file, checking it is the expected suite;
/// `None` if the vectors are not vendored in this copy.
pub fn load(file: &str, algorithm: &str, revision: &str) -> Option<Value> {
    let json = super::vectors::load(file)?;
    let doc: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(doc["algorithm"], algorithm);
    // Not every suite records a revision.
    if !doc["revision"].is_null() {
        assert_eq!(doc["revision"], revision);
    }
    Some(doc)
}

/// The key of `C` from `bytes`, or `None` if it is another width.
/// Each AES width is its own type, so a driver instantiated at one
/// width skips the cases of the other two.
pub fn key_of<C: KeyType>(bytes: &[u8]) -> Option<C::Key> {
    let mut key = C::zero_key();
    if key.as_ref().len() != bytes.len() {
        return None;
    }
    key.as_mut().copy_from_slice(bytes);
    Some(key)
}

/// `C` keyed from `bytes`, or `None` if the width is another type's.
pub fn cipher_of<C: BlockCipher>(bytes: &[u8]) -> Option<C> {
    key_of::<C>(bytes).map(|key| C::new(&key))
}

/// The groups of one test type in a suite for the key width of `C`,
/// each paired with whether it is the encrypt direction. `None` if
/// the vectors are not vendored in this copy, or define nothing at
/// that width, which the driver treats the same way.
pub fn groups<C: KeyType>(
    file: &str,
    algorithm: &str,
    revision: &str,
    test_type: &str,
) -> Option<Vec<(Value, bool)>> {
    let doc = load(file, algorithm, revision)?;
    let bits = 8 * C::zero_key().as_ref().len() as u64;
    let mut selected = Vec::new();
    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["keyLen"].as_u64().is_some_and(|len| len != bits) {
            continue;
        }
        let encrypt = match group["direction"].as_str() {
            Some("encrypt") => true,
            Some("decrypt") => false,
            other => panic!("unknown direction {other:?}"),
        };
        match group["testType"].as_str() {
            Some(t) if t == test_type => {
                selected.push((group.clone(), encrypt))
            }
            Some("AFT") | Some("MCT") => {}
            other => panic!("unknown testType {other:?}"),
        }
    }
    if selected.is_empty() {
        return None;
    }
    Some(selected)
}
