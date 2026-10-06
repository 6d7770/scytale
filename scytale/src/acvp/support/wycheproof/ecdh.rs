//! Wycheproof's ECDH cases on P-256, P-384 and P-521: the public key as a
//! `SubjectPublicKeyInfo` in one pair of files and as a bare SEC 1
//! point in the other, the shared secret checked, and every invalid
//! case refused. The invalid cases are the point: points off the
//! curve, on another curve, with explicit parameters, and the edge
//! cases of the arithmetic, which must all come out as an error and
//! never as a secret.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::super::acvp::hex;
use super::load;
use crate::kex::ecdh::{p256, p384, p521};
use serde_json::Value;

/// Runs every vendored file; each is separately optional.
pub fn run() {
    let mut c = Counts::default();
    file::<P256>("wycheproof/ecdh_secp256r1_test.json", &mut c);
    file::<P256>("wycheproof/ecdh_secp256r1_ecpoint_test.json", &mut c);
    file::<P384>("wycheproof/ecdh_secp384r1_test.json", &mut c);
    file::<P384>("wycheproof/ecdh_secp384r1_ecpoint_test.json", &mut c);
    file::<P521>("wycheproof/ecdh_secp521r1_test.json", &mut c);
    file::<P521>("wycheproof/ecdh_secp521r1_ecpoint_test.json", &mut c);
    if c.files > 0 {
        assert!(c.valid >= 500, "only {} valid cases", c.valid);
        assert!(c.invalid >= 100, "only {} invalid cases", c.invalid);
    }
}

#[derive(Default)]
struct Counts {
    files: usize,
    valid: usize,
    invalid: usize,
}

trait Curve {
    const WIDTH: usize;
    /// The shared secret, or `None` when either key is refused.
    fn agree(private: &[u8], public: &[u8], asn: bool) -> Option<Vec<u8>>;
}

macro_rules! curve {
    ($name:ident, $module:ident, $width:literal) => {
        struct $name;
        impl Curve for $name {
            const WIDTH: usize = $width;
            fn agree(
                private: &[u8],
                public: &[u8],
                asn: bool,
            ) -> Option<Vec<u8>> {
                let private: [u8; $width] = private.try_into().ok()?;
                let key = $module::PrivateKey::try_new(&private).ok()?;
                let peer = if asn {
                    $module::PublicKey::try_from_der(public).ok()?
                } else {
                    $module::PublicKey::try_from_sec1(public).ok()?
                };
                Some(key.shared_secret(&peer).to_vec())
            }
        }
    };
}

curve!(P256, p256, 32);
curve!(P384, p384, 48);
curve!(P521, p521, 66);

/// A big-endian value left-padded to `width`, or `None` when it is
/// wider.
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

fn file<C: Curve>(file: &str, counts: &mut Counts) {
    let Some(doc) = load(file, "ECDH") else {
        return;
    };
    counts.files += 1;
    for group in doc["testGroups"].as_array().expect("testGroups") {
        let asn = match group["encoding"].as_str() {
            Some("asn") => true,
            Some("ecpoint") => false,
            other => panic!("unknown encoding {other:?}"),
        };
        for t in group["tests"].as_array().expect("tests") {
            let tag = format!("tcId {}: {}", t["tcId"], t["comment"]);
            let shared = padded(&t["private"], C::WIDTH)
                .and_then(|d| C::agree(&d, &hex(&t["public"]), asn));
            let accepted = match &shared {
                Some(z) => {
                    assert_eq!(z[..], hex(&t["shared"])[..], "{tag}");
                    true
                }
                None => false,
            };
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
    }
}
