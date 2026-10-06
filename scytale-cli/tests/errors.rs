//! What the tool says when it cannot do what was asked: each message
//! names the command, the option and what would be right, and none
//! shows the bytes of a value.
#![cfg(not(target_family = "wasm"))]

mod common;

use std::fs;

use common::*;

/// The message part of a usage failure, after `scytale <ctx>: `.
fn usage(args: &[&str], stdin: &[u8]) -> String {
    let err = fails(args, stdin, 2);
    err.trim_end().to_owned()
}

#[test]
fn unknown_names_get_suggestions() {
    let e = usage(&["hash", "sha-256"], b"");
    let head = "scytale hash sha-256: no hash named \"sha-256\"; did you \
                mean sha256, ";
    assert!(e.starts_with(head), "{e}");
    assert!(e.ends_with("? (scytale list hash)"), "{e}");
    let e = usage(
        &["aead", "encrypt", "aes-gcm", "-k", KEY16, "-n", NONCE],
        b"",
    );
    assert!(e.starts_with("scytale aead encrypt aes-gcm: no AEAD named"));
    assert!(e.contains("aes-128-gcm"), "{e}");
    let e = usage(&["cipher", "encrypt", "blowfish", "-k", KEY16], b"");
    assert!(e.contains("no cipher named \"blowfish\" (scytale list cipher)"));
    assert!(!e.contains("did you mean"), "{e}");
    let e = usage(&["sig", "sign", "ecdsa", "-k", "x"], b"");
    assert!(e.contains("did you mean ecdsa-sha1"), "{e}");
    let e = usage(&["key", "generate", "rsa"], b"");
    assert!(e.contains("rsa-2048"), "{e}");
}

#[test]
fn lengths_are_stated_and_bytes_are_not() {
    let e = usage(
        &["aead", "encrypt", "aes-256-gcm", "-k", KEY16, "-n", NONCE],
        b"",
    );
    assert_eq!(
        e,
        "scytale aead encrypt aes-256-gcm: --key is 16 bytes; aes-256-gcm \
         takes 32 bytes"
    );
    assert!(!e.contains("0001020304"));
    let e = usage(
        &[
            "aead",
            "encrypt",
            "aes-128-ccm",
            "-k",
            KEY16,
            "-n",
            "hex:0000",
        ],
        b"",
    );
    assert!(e.ends_with("--nonce is 2 bytes; aes-128-ccm takes 7 to 13 bytes"));
    let e = usage(
        &[
            "aead",
            "encrypt",
            "aes-128-ccm",
            "-k",
            KEY16,
            "-n",
            NONCE,
            "--tag-length",
            "7",
        ],
        b"",
    );
    let want = "--tag-length 7: aes-128-ccm takes a tag of an even count \
                from 4 to 16 bytes";
    assert!(e.contains(want), "{e}");
    let e = usage(
        &[
            "cipher",
            "encrypt",
            "aes-128-xts",
            "-k",
            KEY16,
            "--tweak-key",
            KEY16,
            "--iv",
            IV,
        ],
        b"",
    );
    let want = "--key and --tweak-key are the same 16 bytes; XTS needs \
                two different keys";
    assert!(e.contains(want), "{e}");
    let e = usage(&["mac", "tag", "poly1305", "-k", KEY16], b"");
    assert!(
        e.ends_with("--key is 16 bytes; poly1305 takes 32 bytes"),
        "{e}"
    );
}

#[test]
fn values_are_explained() {
    let e = usage(&["mac", "tag", "hmac-sha256", "-k", "0011"], b"");
    assert!(e.contains("--key \"0011\": a value needs a prefix"), "{e}");
    assert!(e.contains("hex:0011 for hex"), "{e}");
    let e = usage(&["mac", "tag", "hmac-sha256", "-k", "hex:0"], b"");
    assert!(e.contains("odd count of hex digits (1)"), "{e}");
    let e = usage(&["mac", "tag", "hmac-sha256", "-k", "hex:0g"], b"");
    assert!(e.contains("\"g\" is not a hex digit"), "{e}");
    let e = usage(&["mac", "tag", "hmac-sha256", "-k", "str:password"], b"");
    assert!(e.contains("scytale kdf pbkdf2"), "{e}");
    let e = usage(
        &["mac", "tag", "hmac-sha256", "-k", "file:/nonexistent/k"],
        b"",
    );
    assert!(e.contains("--key file:/nonexistent/k: No such file"), "{e}");
    let e = usage(
        &["mac", "tag", "hmac-sha256", "-k", "env:SCYTALE_NO_SUCH"],
        b"",
    );
    assert!(e.contains("SCYTALE_NO_SUCH is not set"), "{e}");
    // A long bare value is cut short in the message.
    let e = usage(
        &["mac", "tag", "hmac-sha256", "-k", "00112233445566778899"],
        b"",
    );
    assert!(e.contains("\"00112233..\""), "{e}");
    assert!(!e.contains("445566"), "{e}");
}

#[test]
fn wrong_options_name_the_right_ones() {
    let e = usage(
        &[
            "cipher",
            "encrypt",
            "aes-256-ctr",
            "-k",
            KEY32,
            "--iv",
            IV,
            "--padding",
            "pkcs7",
        ],
        b"",
    );
    assert!(
        e.ends_with(
            "aes-256-ctr takes no --padding; that is for ecb, cbc and cfb128"
        ),
        "{e}"
    );
    let e = usage(
        &["cipher", "encrypt", "chacha20", "-k", KEY32, "--iv", IV],
        b"",
    );
    assert!(
        e.ends_with("chacha20 takes --nonce (12 bytes), not --iv"),
        "{e}"
    );
    let e = usage(&["cipher", "encrypt", "aes-128-kw", "-k", KEY16], b"");
    assert!(
        e.ends_with("aes-128-kw wraps keys; scytale cipher wrap does that"),
        "{e}"
    );
    let e = usage(&["cipher", "wrap", "aes-128-cbc", "-k", KEY16], b"");
    assert!(e.contains("aes-128-kw or aes-128-kwp does"), "{e}");
    let e = usage(
        &[
            "cipher",
            "encrypt",
            "aes-128-cbc",
            "-k",
            KEY16,
            "--padding",
            "pkcs7",
        ],
        b"",
    );
    assert!(
        e.ends_with(
            "--iv is required: one 16-byte block, never reused under a key"
        ),
        "{e}"
    );
    let e = usage(
        &["cipher", "encrypt", "aes-128-cbc", "-k", KEY16, "--iv", IV],
        b"",
    );
    assert!(e.contains("--padding is required for cbc: pkcs7"), "{e}");
    let e = usage(&["hash", "sha256", "--length", "3"], b"");
    assert!(
        e.ends_with("sha256 takes no --length; that is for shake and cshake"),
        "{e}"
    );
    let e = usage(&["hash", "shake128"], b"");
    assert!(
        e.ends_with("shake128 gives any length; say which with --length"),
        "{e}"
    );
    let e = usage(
        &[
            "sig",
            "sign",
            "ecdsa-sha256",
            "-k",
            "x",
            "--context",
            "str:c",
        ],
        b"",
    );
    assert!(e.contains("takes no --context"), "{e}");
    let e = usage(&["hash", "sha256", "--raw", "/dev/null", "/dev/null"], b"");
    assert!(e.contains("--raw with 2 files"), "{e}");
}

#[test]
fn key_files_are_described() {
    let d = dir("errors");
    let ed = d.join("ed.pem");
    let ed = ed.to_str().unwrap();
    ok(&["key", "generate", "ed25519", "-o", ed], b"");
    let ed_pub = d.join("ed.pub");
    let ed_pub = ed_pub.to_str().unwrap();
    ok(&["key", "public", ed, "-o", ed_pub], b"");
    let e = usage(&["sig", "sign", "ecdsa-sha256", "-k", ed], b"m");
    assert_eq!(
        e,
        format!(
            "scytale sig sign ecdsa-sha256: {ed} holds an Ed25519 key; \
             ecdsa-sha256 needs a P-256, P-384 or P-521 key"
        )
    );
    let e = usage(&["sig", "sign", "ed25519", "-k", ed_pub], b"m");
    let want = "holds the public half of an Ed25519 key; ed25519 needs \
                the private key here";
    assert!(e.contains(want), "{e}");
    let e = usage(
        &["sig", "verify", "ed25519", "-p", ed, "-s", "hex:00"],
        b"m",
    );
    let want = "holds an Ed25519 private key; ed25519 needs the public \
                key here, and scytale key public makes it";
    assert!(e.contains(want), "{e}");
    let e = usage(
        &[
            "kem",
            "encapsulate",
            "ml-kem-768",
            "-p",
            ed_pub,
            "--secret-out",
            "/dev/null",
        ],
        b"",
    );
    assert!(
        e.contains("holds an Ed25519 key; ml-kem-768 needs an ML-KEM-768 key"),
        "{e}"
    );
    let junk = d.join("junk");
    fs::write(&junk, "not a key").unwrap();
    let junk = junk.to_str().unwrap();
    let e = usage(&["sig", "sign", "ed25519", "-k", junk], b"m");
    assert!(
        e.contains(&format!("{junk}: not a key file: no PEM block")),
        "{e}"
    );
    let cert = d.join("cert.pem");
    fs::write(
        &cert,
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let e = usage(&["key", "show", cert.to_str().unwrap()], b"");
    assert!(e.contains("not a PRIVATE KEY, PUBLIC KEY"), "{e}");
    let e = usage(&["key", "public", ed_pub], b"");
    assert!(e.contains("already holds the public half"), "{e}");
    let e = fails(&["sig", "sign", "ed25519", "-k", "/nonexistent"], b"m", 3);
    assert!(e.contains("/nonexistent: No such file"), "{e}");
    // Signature shapes.
    let e = usage(
        &["sig", "verify", "ed25519", "-p", ed_pub, "-s", "hex:00"],
        b"m",
    );
    assert!(
        e.ends_with("--signature is 1 byte; ed25519 takes 64 bytes"),
        "{e}"
    );
}

#[test]
fn input_shapes_are_described() {
    let e = usage(
        &[
            "cipher",
            "encrypt",
            "aes-128-cbc",
            "-k",
            KEY16,
            "--iv",
            IV,
            "--padding",
            "none",
        ],
        &[0u8; 17],
    );
    assert!(e.contains("not whole 16-byte blocks (1 left over)"), "{e}");
    let e = usage(
        &["aead", "decrypt", "aes-128-gcm", "-k", KEY16, "-n", NONCE],
        &[0u8; 9],
    );
    let want = "the input is 9 bytes, shorter than the 16-byte tag \
                aes-128-gcm appends";
    assert!(e.ends_with(want), "{e}");
    let e = usage(
        &["cipher", "encrypt", "ff1-aes-128", "-k", KEY16],
        b"12a4\n",
    );
    assert!(
        e.ends_with("line 1: \"a\" is not in the alphabet 0123456789"),
        "{e}"
    );
    let e = usage(&["cipher", "wrap", "aes-128-kw", "-k", KEY16], b"12345");
    assert!(e.contains("whole 8-byte blocks, two or more"), "{e}");
    let e = usage(
        &[
            "cipher",
            "encrypt",
            "aes-128-xts",
            "-k",
            KEY16,
            "--tweak-key",
            KEY32,
            "--iv",
            IV,
        ],
        b"",
    );
    assert!(
        e.contains("--tweak-key is 32 bytes; aes-128-xts takes 16 bytes"),
        "{e}"
    );
}

#[test]
fn verification_failures_say_what_did_not_verify() {
    let sealed = ok(
        &["aead", "encrypt", "aes-128-gcm", "-k", KEY16, "-n", NONCE],
        b"m",
    );
    let mut altered = sealed.clone();
    altered[0] ^= 1;
    let e = fails(
        &["aead", "decrypt", "aes-128-gcm", "-k", KEY16, "-n", NONCE],
        &altered,
        1,
    );
    assert_eq!(
        e.trim_end(),
        "scytale aead decrypt aes-128-gcm: the message did not authenticate \
         under this key, nonce and additional data; nothing was written"
    );
    let e = fails(
        &[
            "mac",
            "verify",
            "hmac-sha256",
            "-k",
            KEY16,
            "-t",
            &format!("hex:{}", "00".repeat(32)),
        ],
        b"m",
        1,
    );
    assert!(e.contains("the tag does not match"), "{e}");
    let e = fails(
        &[
            "cipher",
            "decrypt",
            "aes-128-cbc",
            "-k",
            KEY16,
            "--iv",
            IV,
            "--padding",
            "pkcs7",
        ],
        &[0u8; 32],
        1,
    );
    let want = "the padding is not valid: wrong key, wrong IV, or an \
                altered ciphertext";
    assert!(e.contains(want), "{e}");
    let wrapped =
        ok(&["cipher", "wrap", "aes-128-kw", "-k", KEY16], &[7u8; 16]);
    let other = format!("hex:{}", "ee".repeat(16));
    let unwrap = ["cipher", "unwrap", "aes-128-kw", "-k", &other];
    let e = fails(&unwrap, &wrapped, 1);
    assert!(e.contains("the check value did not verify"), "{e}");
}

#[test]
fn a_closed_pipe_is_quiet() {
    use std::process::{Command, Stdio};
    // `random` writes 1 MiB to a reader that closes at once.
    let mut child = Command::new(BIN)
        .args(["random", "1048576", "--raw"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
}
