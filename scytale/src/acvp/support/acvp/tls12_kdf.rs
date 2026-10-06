//! TLS v1.2 KDF (RFC 7627): the extended master secret from the
//! premaster secret and the session hash, then the key block from
//! it and the two randoms, under the cipher suite's hash. Every
//! group in the vendored file is the extended form; the RFC 5246
//! form is the same function with another label and seed.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::{hex, load};
use crate::BlockType;
use crate::hash::Hash;
use crate::hash::sha2::{Sha256, Sha384, Sha512};
use crate::kdf::tls12;
use serde_json::Value;

/// Runs the suite; a no-op without the vendored vectors.
pub fn run() {
    let file = "TLS-v1.2-KDF-RFC7627/internalProjection.json";
    let Some(doc) = load(file, "TLS-v1.2", "RFC7627") else {
        return;
    };
    let mut cases = 0;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["tlsVersion"], "v1.2_ems");
        let key_block_len =
            group["keyBlockLength"].as_u64().expect("keyBlockLength") as usize
                / 8;
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tgId {} tcId {}", group["tgId"], t["tcId"]);
            match group["hashAlg"].as_str().expect("hashAlg") {
                "SHA2-256" => case::<Sha256>(t, key_block_len, &tag),
                "SHA2-384" => case::<Sha384>(t, key_block_len, &tag),
                "SHA2-512" => case::<Sha512>(t, key_block_len, &tag),
                other => panic!("unknown hash {other}"),
            }
            cases += 1;
        }
    }
    assert!(cases >= 120, "only {cases} TLS 1.2 KDF cases");
}

fn case<H: Hash + Clone + BlockType + Default>(
    t: &Value,
    key_block_len: usize,
    tag: &str,
) {
    let premaster = hex(&t["preMasterSecret"]);
    let session_hash = hex(&t["sessionHash"]);
    let mut master = vec![0u8; 48];
    tls12::prf::<H>(
        &premaster,
        b"extended master secret",
        &[&session_hash],
        &mut master,
    );
    assert_eq!(master, hex(&t["masterSecret"]), "{tag}");

    let server_random = hex(&t["serverRandom"]);
    let client_random = hex(&t["clientRandom"]);
    let mut key_block = vec![0u8; key_block_len];
    tls12::prf::<H>(
        &master,
        b"key expansion",
        &[&server_random, &client_random],
        &mut key_block,
    );
    assert_eq!(key_block, hex(&t["keyBlock"]), "{tag}");
}
