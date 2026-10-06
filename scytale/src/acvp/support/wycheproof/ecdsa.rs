//! Wycheproof's ECDSA verification cases on P-256, P-384 and P-521, in
//! both signature forms: the DER `ECDSA-Sig-Value` files, whose
//! invalid cases are mostly encodings bent every way ASN.1 allows,
//! and the P1363 `r || s` files, whose invalid cases are arithmetic.
//! Each group's key also comes in DER and PEM, which checks the
//! curve key formats against an external writer.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::super::acvp::hex;
use super::load;
use crate::hash::Hash;
use crate::hash::sha2::{Sha256, Sha384, Sha512};
use crate::sig::ecdsa::{p256, p384, p521};
use serde_json::Value;

/// Runs every vendored file; each is separately optional.
pub fn run() {
    let mut c = Counts::default();
    der::<P256, Sha256>("wycheproof/ecdsa_secp256r1_sha256_test.json", &mut c);
    der::<P384, Sha384>("wycheproof/ecdsa_secp384r1_sha384_test.json", &mut c);
    der::<P521, Sha512>("wycheproof/ecdsa_secp521r1_sha512_test.json", &mut c);
    fixed::<P256, Sha256>(
        "wycheproof/ecdsa_secp256r1_sha256_p1363_test.json",
        &mut c,
    );
    fixed::<P384, Sha384>(
        "wycheproof/ecdsa_secp384r1_sha384_p1363_test.json",
        &mut c,
    );
    fixed::<P521, Sha512>(
        "wycheproof/ecdsa_secp521r1_sha512_p1363_test.json",
        &mut c,
    );
    if c.files > 0 {
        assert!(c.valid >= 400, "only {} valid cases", c.valid);
        assert!(c.invalid >= 600, "only {} invalid cases", c.invalid);
    }
}

#[derive(Default)]
struct Counts {
    files: usize,
    valid: usize,
    invalid: usize,
}

/// One curve's public key type and signature width.
trait Curve {
    const WIDTH: usize;
    type Public;
    fn public(group: &Value) -> Self::Public;
    fn from_der(der: &[u8]) -> Option<Vec<u8>>;
    fn verify<H: Hash + Default>(
        key: &Self::Public,
        msg: &[u8],
        sig: &[u8],
    ) -> bool;
}

macro_rules! curve {
    ($name:ident, $module:ident, $width:literal) => {
        struct $name;
        impl Curve for $name {
            const WIDTH: usize = $width;
            type Public = $module::PublicKey;

            /// The group's key from its uncompressed point, after
            /// checking that its DER and PEM name the same key and
            /// come back out unchanged.
            fn public(group: &Value) -> Self::Public {
                let sec1 = hex(&group["publicKey"]["uncompressed"]);
                let key =
                    $module::PublicKey::try_from_sec1(&sec1).expect("key");
                let der = hex(&group["publicKeyDer"]);
                let pem = group["publicKeyPem"].as_str().expect("pem");
                let from_der =
                    $module::PublicKey::try_from_der(&der).expect("der");
                let from_pem = $module::PublicKey::try_from_pem(pem.as_bytes())
                    .expect("pem");
                assert_eq!(from_der.sec1_bytes()[..], sec1[..]);
                assert_eq!(from_pem.sec1_bytes()[..], sec1[..]);
                let mut out = [0u8; 512];
                let n = key.der_bytes(&mut out).expect("export der");
                assert_eq!(out[..n], der[..]);
                let n = key.pem_bytes(&mut out).expect("export pem");
                assert_eq!(&out[..n], pem.as_bytes());
                key
            }

            fn from_der(der: &[u8]) -> Option<Vec<u8>> {
                $module::signature_from_der(der).ok().map(|s| s.to_vec())
            }

            fn verify<H: Hash + Default>(
                key: &Self::Public,
                msg: &[u8],
                sig: &[u8],
            ) -> bool {
                match <[u8; 2 * $width]>::try_from(sig) {
                    Ok(sig) => key.verify::<H>(msg, &sig).is_ok(),
                    Err(_) => false,
                }
            }
        }
    };
}

curve!(P256, p256, 32);
curve!(P384, p384, 48);
curve!(P521, p521, 66);

fn der<C: Curve, H: Hash + Default>(file: &str, counts: &mut Counts) {
    let Some(doc) = load(file, "ECDSA") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["type"], "EcdsaVerify");
        let key = C::public(group);
        for t in group["tests"].as_array().expect("tests") {
            let accepted = match C::from_der(&hex(&t["sig"])) {
                Some(sig) => C::verify::<H>(&key, &hex(&t["msg"]), &sig),
                None => false,
            };
            judge(t, accepted, counts);
        }
    }
}

fn fixed<C: Curve, H: Hash + Default>(file: &str, counts: &mut Counts) {
    let Some(doc) = load(file, "ECDSA") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        assert_eq!(group["type"], "EcdsaP1363Verify");
        let key = C::public(group);
        for t in group["tests"].as_array().expect("tests") {
            let accepted =
                C::verify::<H>(&key, &hex(&t["msg"]), &hex(&t["sig"]));
            judge(t, accepted, counts);
        }
    }
}

/// Compares an outcome with the file's verdict. An `acceptable`
/// case is legal either way; the counts still see it.
fn judge(t: &Value, accepted: bool, counts: &mut Counts) {
    let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
    match t["result"].as_str() {
        Some("valid") => {
            assert!(accepted, "{tag} rejected");
            counts.valid += 1;
        }
        Some("invalid") => {
            assert!(!accepted, "{tag} accepted");
            counts.invalid += 1;
        }
        Some("acceptable") => {
            if accepted {
                counts.valid += 1;
            } else {
                counts.invalid += 1;
            }
        }
        other => panic!("{tag}: unknown result {other:?}"),
    }
}
