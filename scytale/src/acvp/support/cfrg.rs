//! The CFRG's HPKE test vectors (RFC 9180 appendix A, and the fuller
//! set the draft's repository carries): for each suite, the recipient
//! and ephemeral keys from their seeds, the encapsulation, the
//! context's nonce base and exporter secret, a run of encryptions in
//! order, and exports. Base mode only, and the KEMs, KDFs and AEADs
//! the module has: X448 and the export-only AEAD are skipped.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

use super::acvp::hex;
use super::vectors;
use crate::aead::{ChaCha20Poly1305, Gcm};
use crate::cipher::aes::{Aes128, Aes256};
use crate::hash::sha2::{Sha256, Sha384, Sha512};
use crate::pke::hpke::{self, Cipher, Kdf};
use serde_json::Value;

/// Runs every vector; a no-op without the vendored file.
pub fn run() {
    let Some(text) = vectors::load("hpke/test-vectors.json") else {
        return;
    };
    let doc: Value = serde_json::from_str(&text).expect("valid JSON");
    let mut suites = 0;
    for v in doc.as_array().expect("an array of vectors") {
        if v["mode"] != 0 {
            continue;
        }
        let ran = match v["kem_id"].as_u64() {
            Some(0x10) => with_kdf!(v, p256),
            Some(0x12) => with_kdf!(v, p521),
            Some(0x20) => with_kdf!(v, x25519),
            _ => false,
        };
        suites += usize::from(ran);
    }
    // P-256, P-521 and X25519, each with two KDFs and three AEADs.
    assert!(suites >= 18, "only {suites} HPKE suites");
}

/// Picks the KDF, then the AEAD, and runs the case; `false` for an
/// identifier the module does not have.
macro_rules! with_kdf {
    ($v:expr, $kem:ident) => {
        match $v["kdf_id"].as_u64() {
            Some(1) => with_aead!($v, $kem, Sha256),
            Some(2) => with_aead!($v, $kem, Sha384),
            Some(3) => with_aead!($v, $kem, Sha512),
            _ => false,
        }
    };
}

macro_rules! with_aead {
    ($v:expr, $kem:ident, $h:ty) => {
        match $v["aead_id"].as_u64() {
            Some(1) => case!($v, $kem, $h, Gcm<Aes128>),
            Some(2) => case!($v, $kem, $h, Gcm<Aes256>),
            Some(3) => case!($v, $kem, $h, ChaCha20Poly1305),
            _ => false,
        }
    };
}

macro_rules! case {
    ($v:expr, $kem:ident, $h:ty, $a:ty) => {{
        use hpke::$kem::PrivateKey;
        let v = $v;
        let tag = format!(
            "kem {} kdf {} aead {}",
            v["kem_id"], v["kdf_id"], v["aead_id"]
        );
        let recipient = PrivateKey::from_seed(&hex(&v["ikmR"])).expect("ikmR");
        let ephemeral = PrivateKey::from_seed(&hex(&v["ikmE"])).expect("ikmE");
        assert_eq!(recipient.secret_bytes()[..], hex(&v["skRm"])[..], "{tag}");
        assert_eq!(
            recipient.public_key().bytes()[..],
            hex(&v["pkRm"])[..],
            "{tag}"
        );
        assert_eq!(ephemeral.secret_bytes()[..], hex(&v["skEm"])[..], "{tag}");
        assert_eq!(
            ephemeral.public_key().bytes()[..],
            hex(&v["pkEm"])[..],
            "{tag}"
        );
        let info = hex(&v["info"]);
        let (enc, mut sender) = recipient
            .public_key()
            .sender_with::<$h, $a>(&ephemeral, &info)
            .expect("sender");
        assert_eq!(enc[..], hex(&v["enc"])[..], "{tag}");
        let mut receiver = recipient
            .recipient::<$h, $a>(&enc, &info)
            .expect("recipient");
        check(&mut sender, &mut receiver, v, &tag);
        true
    }};
}

use {case, with_aead, with_kdf};

/// The context's own values, every encryption in order both ways,
/// and every export from both sides.
fn check<H: Kdf, A: Cipher>(
    sender: &mut hpke::Context<H, A>,
    receiver: &mut hpke::Context<H, A>,
    v: &Value,
    tag: &str,
) {
    assert_eq!(sender.base_nonce[..], hex(&v["base_nonce"])[..], "{tag}");
    let nh = size_of::<H::Output>();
    assert_eq!(
        sender.exporter[..nh],
        hex(&v["exporter_secret"])[..],
        "{tag}"
    );
    for (i, e) in v["encryptions"]
        .as_array()
        .expect("encryptions")
        .iter()
        .enumerate()
    {
        let aad = hex(&e["aad"]);
        assert_eq!(
            sender.nonce().expect("nonce")[..],
            hex(&e["nonce"])[..],
            "{tag} #{i}"
        );
        let mut data = hex(&e["pt"]);
        let mut mac = [0u8; hpke::TAG_SIZE];
        sender.encrypt(&aad, &mut data, &mut mac).expect("encrypt");
        data.extend_from_slice(&mac);
        assert_eq!(data, hex(&e["ct"]), "{tag} #{i}");
        let n = data.len() - hpke::TAG_SIZE;
        receiver
            .decrypt(&aad, &mut data[..n], &mac)
            .expect("decrypt");
        assert_eq!(data[..n], hex(&e["pt"])[..], "{tag} #{i}");
    }
    for e in v["exports"].as_array().expect("exports") {
        let context = hex(&e["exporter_context"]);
        let len = e["L"].as_u64().expect("L") as usize;
        let mut ours = vec![0u8; len];
        let mut theirs = vec![0u8; len];
        sender.export(&context, &mut ours).expect("export");
        receiver.export(&context, &mut theirs).expect("export");
        assert_eq!(ours, hex(&e["exported_value"]), "{tag}");
        assert_eq!(theirs, ours, "{tag}");
    }
}
