//! The binary, end to end: every family round-trips through the
//! command line, wrong input is refused with the right status, and
//! where openssl is on the machine the formats agree with it.
//!
//! The binary is run as a process, which wasm has no way to do; the
//! unit tests inside it still run there.
#![cfg(not(target_family = "wasm"))]

mod common;

use std::fs;

use common::*;

#[test]
fn hash_matches_the_vectors() {
    let out = text(ok(&["hash", "sha256"], b"abc"));
    assert_eq!(
        out,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -"
    );
    let out = text(ok(&["hash", "sha3-256"], b""));
    assert!(out.starts_with("a7ffc6f8bf1ed76651c14756a061d662"));
    let out = text(ok(&["hash", "shake128", "--length", "16"], b""));
    assert_eq!(out, "7f9c2ba4e88f827d616045507605853e  -");
    let out = ok(&["hash", "sha256", "--raw"], b"abc");
    assert_eq!(out.len(), 32);
    // Names are forgiving of case and underscores.
    let out = text(ok(&["hash", "SHA3_256"], b""));
    assert!(out.starts_with("a7ffc6f8"));
    // The algorithm is not optional.
    fails(&["hash"], b"", 2);
}

#[test]
fn aead_round_trips_and_detects_tampering() {
    for alg in [
        "aes-128-gcm",
        "aes-128-gcm-siv",
        "aes-128-ccm",
        "chacha20-poly1305",
    ] {
        let key = if alg == "chacha20-poly1305" {
            KEY32
        } else {
            KEY16
        };
        let message = b"the quick brown fox".repeat(1000);
        let enc = [
            "aead",
            "encrypt",
            alg,
            "-k",
            key,
            "-n",
            NONCE,
            "--aad",
            "str:header",
        ];
        let mut sealed = ok(&enc, &message);
        assert_eq!(sealed.len(), message.len() + 16);
        let dec = [
            "aead",
            "decrypt",
            alg,
            "-k",
            key,
            "-n",
            NONCE,
            "--aad",
            "str:header",
        ];
        assert_eq!(ok(&dec, &sealed), message);
        // A flipped bit, the wrong aad, and a short input.
        sealed[5] ^= 1;
        let out = run(&dec, &sealed);
        assert_eq!(out.status.code(), Some(1), "{alg}");
        assert!(out.stdout.is_empty(), "{alg}: plaintext leaked");
        sealed[5] ^= 1;
        let wrong = [
            "aead",
            "decrypt",
            alg,
            "-k",
            key,
            "-n",
            NONCE,
            "--aad",
            "str:other",
        ];
        fails(&wrong, &sealed, 1);
        fails(&dec, &sealed[..8], 2);
    }
    // XPN: a 24-byte nonce.
    let nonce = "hex:000000000000000000000001000000000000000000000002";
    let enc = ["aead", "encrypt", "aes-256-xpn", "-k", KEY32, "-n", nonce];
    let dec = ["aead", "decrypt", "aes-256-xpn", "-k", KEY32, "-n", nonce];
    let sealed = ok(&enc, b"xpn");
    assert_eq!(ok(&dec, &sealed), b"xpn");
    // GCM with a truncated tag.
    let enc = [
        "aead",
        "encrypt",
        "aes-128-gcm",
        "-k",
        KEY16,
        "-n",
        NONCE,
        "--tag-length",
        "12",
    ];
    let dec = [
        "aead",
        "decrypt",
        "aes-128-gcm",
        "-k",
        KEY16,
        "-n",
        NONCE,
        "--tag-length",
        "12",
    ];
    let sealed = ok(&enc, b"short tag");
    assert_eq!(sealed.len(), 9 + 12);
    assert_eq!(ok(&dec, &sealed), b"short tag");
}

#[test]
fn gcm_matches_the_nist_vector() {
    // GCM test case 2 from the GCM specification: zero key, zero IV,
    // one zero block.
    let zero_key = format!("hex:{}", "00".repeat(16));
    let zero_nonce = format!("hex:{}", "00".repeat(12));
    let out = ok(
        &[
            "aead",
            "encrypt",
            "aes-128-gcm",
            "-k",
            &zero_key,
            "-n",
            &zero_nonce,
        ],
        &[0u8; 16],
    );
    assert_eq!(
        hex(&out),
        "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    );
}

#[test]
fn every_cipher_mode_round_trips() {
    let message: Vec<u8> = (0..100_003u32).map(|i| (i * 7) as u8).collect();
    for alg in [
        "aes-128-ecb",
        "aes-192-cbc",
        "aes-256-ctr",
        "aes-128-cfb1",
        "aes-128-cfb8",
        "aes-256-cfb128",
        "aes-128-ofb",
    ] {
        let mut enc = vec!["cipher", "encrypt", alg, "-k"];
        let key = match &alg[4..7] {
            "128" => KEY16.to_owned(),
            "192" => format!("hex:{}", "01".repeat(24)),
            _ => KEY32.to_owned(),
        };
        enc.push(&key);
        if alg != "aes-128-ecb" {
            enc.extend(["--iv", IV]);
        }
        let padded =
            matches!(alg, "aes-128-ecb" | "aes-192-cbc" | "aes-256-cfb128");
        if padded {
            enc.extend(["--padding", "pkcs7"]);
        }
        let mut dec = enc.clone();
        dec[1] = "decrypt";
        let ciphertext = ok(&enc, &message);
        if padded {
            let blocks = (message.len() / 16 + 1) * 16;
            assert_eq!(ciphertext.len(), blocks, "{alg}");
        } else {
            assert_eq!(ciphertext.len(), message.len(), "{alg}");
        }
        assert_eq!(ok(&dec, &ciphertext), message, "{alg}");
        assert_ne!(&ciphertext[..message.len()], &message[..], "{alg}");
    }
    // Without padding, a partial block is refused; a whole one passes.
    let enc = [
        "cipher",
        "encrypt",
        "aes-128-cbc",
        "-k",
        KEY16,
        "--iv",
        IV,
        "--padding",
        "none",
    ];
    fails(&enc, &message, 2);
    assert_eq!(ok(&enc, &message[..32]).len(), 32);
    // Padding that does not check on decrypt is status 1.
    let dec = [
        "cipher",
        "decrypt",
        "aes-128-cbc",
        "-k",
        KEY16,
        "--iv",
        IV,
        "--padding",
        "pkcs7",
    ];
    fails(&dec, &[0u8; 32], 1);
}

#[test]
fn xts_kw_chacha20_and_fpe() {
    // XTS takes both keys, and they must differ.
    let second = format!("hex:{}", "ff".repeat(16));
    let enc = [
        "cipher",
        "encrypt",
        "aes-128-xts",
        "-k",
        KEY16,
        "--tweak-key",
        &second,
        "--iv",
        IV,
    ];
    let dec = [
        "cipher",
        "decrypt",
        "aes-128-xts",
        "-k",
        KEY16,
        "--tweak-key",
        &second,
        "--iv",
        IV,
    ];
    let sector = [0x5au8; 520];
    let c = ok(&enc, &sector);
    assert_eq!(c.len(), 520);
    assert_eq!(ok(&dec, &c), sector);

    // Key wrap: RFC 3394 4.1.
    let kek = "hex:000102030405060708090A0B0C0D0E0F";
    let wrapped = ok(
        &["cipher", "wrap", "aes-128-kw", "-k", kek],
        &hex_bytes("00112233445566778899AABBCCDDEEFF"),
    );
    assert_eq!(
        hex(&wrapped),
        "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
    );
    let back = ok(&["cipher", "unwrap", "aes-128-kw", "-k", kek], &wrapped);
    assert_eq!(hex(&back), "00112233445566778899aabbccddeeff");
    let kwp = ok(&["cipher", "wrap", "aes-256-kwp", "-k", KEY32], b"12345");
    assert_eq!(kwp.len(), 16);
    let back = ok(&["cipher", "unwrap", "aes-256-kwp", "-k", KEY32], &kwp);
    assert_eq!(back, b"12345");

    // ChaCha20: RFC 8439 2.4.2 uses a counter of 1.
    let nonce = "hex:000000000000004a00000000";
    let out = ok(
        &[
            "cipher",
            "encrypt",
            "chacha20",
            "-k",
            KEY32,
            "--nonce",
            nonce,
            "--counter",
            "1",
        ],
        b"Ladies and Gentlemen of the class of '99: If I could offer you \
          only one tip for the future, sunscreen would be it.",
    );
    assert!(hex(&out).starts_with("6e2e359a2568f98041ba0728dd0d6981"));

    // FF1 over digits, one line at a time.
    let enc = ["cipher", "encrypt", "ff1-aes-128", "-k", KEY16];
    let dec = ["cipher", "decrypt", "ff1-aes-128", "-k", KEY16];
    let c = text(ok(&enc, b"4000123456789010\n0123456789\n"));
    let lines: Vec<&str> = c.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].len(), 16);
    assert!(lines[0].bytes().all(|b| b.is_ascii_digit()));
    assert_ne!(lines[0], "4000123456789010");
    let back = text(ok(&dec, format!("{c}\n").as_bytes()));
    assert_eq!(back, "4000123456789010\n0123456789");
    // FF3-1 with a 7-byte tweak and a custom alphabet.
    let enc = [
        "cipher",
        "encrypt",
        "ff3-1-aes-256",
        "-k",
        KEY32,
        "--tweak",
        "hex:00000000000000",
        "--alphabet",
        "abcdefghijklmnopqrstuvwxyz",
    ];
    let c = text(ok(&enc, b"helloworld\n"));
    assert_eq!(c.len(), 10);
    assert!(c.bytes().all(|b| b.is_ascii_lowercase()));
}

#[test]
fn mac_and_kdf() {
    // RFC 4231 test case 2.
    let out = text(ok(
        &["mac", "tag", "hmac-sha256", "-k", "hex:4a656665"],
        b"what do ya want for nothing?",
    ));
    assert_eq!(
        out,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    let tag = format!("hex:{out}");
    let good = [
        "mac",
        "verify",
        "hmac-sha256",
        "-k",
        "hex:4a656665",
        "-t",
        &tag,
    ];
    ok(&good, b"what do ya want for nothing?");
    fails(&good, b"what do ya want for something?", 1);
    // CMAC, KMAC and Poly1305 run and have the right sizes.
    let cmac = text(ok(&["mac", "tag", "cmac-aes-256", "-k", KEY32], b""));
    assert_eq!(cmac.len(), 32);
    let kmac = ok(
        &[
            "mac",
            "tag",
            "kmac128",
            "-k",
            KEY32,
            "--length",
            "8",
            "--customization",
            "str:x",
        ],
        b"m",
    );
    assert_eq!(text(kmac).len(), 16);
    let poly = text(ok(&["mac", "tag", "poly1305", "-k", KEY32], b"m"));
    assert_eq!(poly.len(), 32);

    // RFC 5869 test case 1.
    let ikm = format!("hex:{}", "0b".repeat(22));
    let out = text(ok(
        &[
            "kdf",
            "hkdf",
            "sha256",
            "--ikm",
            &ikm,
            "--salt",
            "hex:000102030405060708090a0b0c",
            "--info",
            "hex:f0f1f2f3f4f5f6f7f8f9",
            "--length",
            "42",
        ],
        b"",
    ));
    assert_eq!(
        out,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865"
    );
    // RFC 6070 test case 2.
    let out = text(ok(
        &[
            "kdf",
            "pbkdf2",
            "sha1",
            "--password",
            "str:password",
            "--salt",
            "str:salt",
            "--iterations",
            "2",
            "--length",
            "20",
        ],
        b"",
    ));
    assert_eq!(out, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    // The IETF TLS 1.2 PRF vector for SHA-256, with the seed in two
    // parts.
    let out = text(ok(
        &[
            "kdf",
            "tls12",
            "sha256",
            "--secret",
            "hex:9bbe436ba940f017b17652849a71db35",
            "--label",
            "str:test label",
            "--seed",
            "hex:a0ba9f936cda3118",
            "--seed",
            "hex:27a6f796ffd5198c",
            "--length",
            "32",
        ],
        b"",
    ));
    assert_eq!(
        out,
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
    );
}

#[test]
fn random_is_random() {
    let a = text(ok(&["random", "32"], b""));
    let b = text(ok(&["random", "32"], b""));
    assert_eq!(a.len(), 64);
    assert_ne!(a, b);
    assert_eq!(ok(&["random", "70000", "--raw"], b"").len(), 70000);
}

#[test]
fn every_key_algorithm_signs_agrees_or_encapsulates() {
    let d = dir("pk");
    let message = b"a message to sign";
    for (alg, scheme) in [
        ("ed25519", "ed25519"),
        ("ecdsa-p256", "ecdsa-sha256"),
        ("ecdsa-p384", "ecdsa-sha384"),
        ("ecdsa-p521", "ecdsa-sha512"),
        ("rsa-1024", "rsa-pss-sha256"),
        ("ml-dsa-44", "ml-dsa-44"),
        ("slh-dsa-shake-128f", "slh-dsa-shake-128f"),
    ] {
        let private = d.join(format!("{alg}.pem"));
        let public = d.join(format!("{alg}.pub"));
        let (private, public) =
            (private.to_str().unwrap(), public.to_str().unwrap());
        ok(&["key", "generate", alg, "-o", private], b"");
        let pem = fs::read_to_string(private).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        ok(&["key", "public", private, "-o", public], b"");
        let pem = fs::read_to_string(public).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        let shown = text(ok(&["key", "show", private], b""));
        assert!(shown.contains("private key"), "{shown}");
        let sig = ok(&["sig", "sign", scheme, "-k", private], message);
        let sig_hex = format!("hex:{}", hex(&sig));
        let verify = ["sig", "verify", scheme, "-p", public, "-s", &sig_hex];
        ok(&verify, message);
        fails(&verify, b"another", 1);
        if alg.starts_with("ecdsa") {
            let raw = ok(
                &["sig", "sign", scheme, "-k", private, "--raw-ecdsa"],
                message,
            );
            let raw_hex = format!("hex:{}", hex(&raw));
            let mut verify = vec!["sig", "verify", scheme, "-p", public];
            verify.extend(["-s", &raw_hex]);
            fails(&verify, message, 2);
            verify.push("--raw-ecdsa");
            ok(&verify, message);
        }
        if alg == "rsa-1024" {
            let pkcs1 = "rsa-pkcs1-sha256";
            let sig = ok(&["sig", "sign", pkcs1, "-k", private], message);
            let sig_hex = format!("hex:{}", hex(&sig));
            let verify = ["sig", "verify", pkcs1, "-p", public, "-s", &sig_hex];
            ok(&verify, message);
            let wrong = ["sig", "verify", scheme, "-p", public, "-s", &sig_hex];
            fails(&wrong, message, 1);
            let shown = text(ok(&["key", "show", public], b""));
            assert!(shown.contains("1024 bits"));
            // RSA-OAEP too.
            let oaep = "rsa-oaep-sha256";
            let c = ok(
                &["pke", "encrypt", oaep, "-p", public, "--label", "str:l"],
                b"secret",
            );
            assert_eq!(c.len(), 128);
            let back = ok(
                &["pke", "decrypt", oaep, "-k", private, "--label", "str:l"],
                &c,
            );
            assert_eq!(back, b"secret");
            fails(&["pke", "decrypt", oaep, "-k", private], &c, 1);
        }
    }
    // Context strings on the algorithms that take them.
    let private = d.join("ed25519.pem").to_str().unwrap().to_owned();
    let public = d.join("ed25519.pub").to_str().unwrap().to_owned();
    let sig = ok(
        &[
            "sig",
            "sign",
            "ed25519",
            "-k",
            &private,
            "--context",
            "str:ctx",
        ],
        message,
    );
    let sig_hex = format!("hex:{}", hex(&sig));
    let mut verify = vec!["sig", "verify", "ed25519", "-p", &public];
    verify.extend(["-s", &sig_hex]);
    fails(&verify, message, 1);
    verify.extend(["--context", "str:ctx"]);
    ok(&verify, message);

    // Key agreement: both sides reach the same secret.
    for alg in ["x25519", "ecdh-p256", "ecdh-p384", "ecdh-p521"] {
        let a = d.join(format!("{alg}-a.pem"));
        let b = d.join(format!("{alg}-b.pem"));
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());
        let a_pub = format!("{a}.pub");
        let b_pub = format!("{b}.pub");
        ok(&["key", "generate", alg, "-o", a], b"");
        ok(&["key", "generate", alg, "-o", b], b"");
        ok(&["key", "public", a, "-o", &a_pub], b"");
        ok(&["key", "public", b, "-o", &b_pub], b"");
        let ab = ok(&["kex", "agree", alg, "-k", a, "-p", &b_pub], b"");
        let ba = ok(&["kex", "agree", alg, "-k", b, "-p", &a_pub], b"");
        assert_eq!(ab, ba, "{alg}");
        let len = match alg {
            "ecdh-p384" => 96,
            "ecdh-p521" => 132,
            _ => 64,
        };
        assert_eq!(text(ab).len(), len);
    }

    // Encapsulation: the secret written aside equals the one
    // decapsulated.
    for alg in ["ml-kem-512", "ml-kem-1024"] {
        let private = d.join(format!("{alg}.pem"));
        let public = d.join(format!("{alg}.pub"));
        let secret = d.join(format!("{alg}.ss"));
        let (private, public, secret) = (
            private.to_str().unwrap(),
            public.to_str().unwrap(),
            secret.to_str().unwrap(),
        );
        ok(&["key", "generate", alg, "-o", private], b"");
        ok(&["key", "public", private, "-o", public], b"");
        let encapsulate = [
            "kem",
            "encapsulate",
            alg,
            "-p",
            public,
            "--secret-out",
            secret,
        ];
        let ciphertext = ok(&encapsulate, b"");
        let decapsulate = ["kem", "decapsulate", alg, "-k", private];
        let ss = ok(&decapsulate, &ciphertext);
        assert_eq!(text(ss), hex(&fs::read(secret).unwrap()));
    }
}

#[test]
fn list_names_only_what_runs() {
    let all = text(ok(&["list"], b""));
    assert!(all.lines().count() > 150);
    let families = [
        "hash", "mac", "aead", "cipher", "kdf", "key", "sig", "kex", "kem",
        "pke",
    ];
    for family in families {
        let names = text(ok(&["list", family], b""));
        assert!(names.lines().count() >= 3, "{family}");
        for name in names.lines() {
            assert!(all.contains(&format!("{family} {name}")));
        }
        let long = text(ok(&["list", family, "--long"], b""));
        assert_eq!(long.lines().count(), names.lines().count());
    }
    fails(&["list", "kdfs"], b"", 2);
    // Every named algorithm gets past the name check in its command.
    let one = "hex:00";
    for name in text(ok(&["list", "cipher"], b"")).lines() {
        let verb = if name.contains("-kw") {
            "wrap"
        } else {
            "encrypt"
        };
        let err = fails(&["cipher", verb, name, "-k", one], b"", 2);
        assert!(!err.contains("named"), "{name}: {err}");
    }
    for name in text(ok(&["list", "aead"], b"")).lines() {
        let args = ["aead", "encrypt", name, "-k", one, "-n", one];
        let err = fails(&args, b"", 2);
        assert!(!err.contains("named"), "{name}: {err}");
    }
    for name in text(ok(&["list", "mac"], b"")).lines() {
        let err = fails(&["mac", "tag", name, "-k", "00"], b"", 2);
        assert!(!err.contains("named"), "{name}: {err}");
    }
    for name in text(ok(&["list", "sig"], b"")).lines() {
        let args = ["sig", "sign", name, "-k", "/nonexistent"];
        let err = fails(&args, b"", 3);
        assert!(!err.contains("named"), "{name}: {err}");
    }
    for name in text(ok(&["list", "pke"], b"")).lines() {
        let args = ["pke", "encrypt", name, "-p", "/nonexistent"];
        let err = fails(&args, b"", 3);
        assert!(!err.contains("named"), "{name}: {err}");
    }
    for name in text(ok(&["list", "kdf"], b"")).lines() {
        let args = ["kdf", "hkdf", name, "--ikm", "00", "-l", "1"];
        let err = fails(&args, b"", 2);
        assert!(!err.contains("named"), "{name}: {err}");
    }
}

#[test]
fn agrees_with_openssl_where_it_is_present() {
    let message = b"fourteen bytes".repeat(37);
    let Some(theirs) = openssl(
        &["enc", "-aes-128-cbc", "-K", &KEY16[4..], "-iv", &IV[4..]],
        &message,
    ) else {
        eprintln!("openssl not found; skipping");
        return;
    };
    let cbc = |verb| {
        [
            "cipher",
            verb,
            "aes-128-cbc",
            "-k",
            KEY16,
            "--iv",
            IV,
            "--padding",
            "pkcs7",
        ]
    };
    assert_eq!(ok(&cbc("encrypt"), &message), theirs, "CBC with PKCS#7");
    assert_eq!(ok(&cbc("decrypt"), &theirs), message);

    // A key openssl made, read here; a key made here, read there.
    let d = dir("openssl");
    let key = d.join("ec.pem");
    let key = key.to_str().unwrap();
    let params = ["ecparam", "-genkey", "-name", "prime256v1", "-noout"];
    if let Some(pem) = openssl(&params, b"") {
        fs::write(key, pem).unwrap();
        let shown = text(ok(&["key", "show", key], b""));
        assert_eq!(shown, "P-256 private key");
        let public = d.join("ec.pub");
        let public = public.to_str().unwrap();
        ok(&["key", "public", key, "-o", public], b"");
        let sig = ok(&["sig", "sign", "ecdsa-sha256", "-k", key], &message);
        let sig_path = d.join("ec.sig");
        fs::write(&sig_path, &sig).unwrap();
        let verified = openssl(
            &[
                "dgst",
                "-sha256",
                "-verify",
                public,
                "-signature",
                sig_path.to_str().unwrap(),
            ],
            &message,
        );
        assert!(verified.is_some(), "openssl rejected our ECDSA signature");
    }
    let ours = d.join("ed.pem");
    let ours = ours.to_str().unwrap();
    ok(&["key", "generate", "ed25519", "-o", ours], b"");
    if let Some(theirs) = openssl(&["pkey", "-in", ours, "-pubout"], b"") {
        let public = ok(&["key", "public", ours], b"");
        assert_eq!(public, theirs);
    }
}

/// Every option `--help` shows, at every level, and every name `list`
/// prints, is in the manual; the manual is not left behind the code.
#[test]
fn the_manual_covers_the_help() {
    let manual = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scytale.1"),
    )
    .unwrap();
    // troff escapes hyphens.
    let manual = manual.replace("\\-", "-");
    let mut missing = Vec::new();
    let mut stack = vec![Vec::<String>::new()];
    while let Some(path) = stack.pop() {
        let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
        args.push("--help");
        let help = String::from_utf8(ok(&args, b"")).unwrap();
        let mut section = "";
        for line in help.lines() {
            if line.ends_with(':') && !line.starts_with(' ') {
                section = line;
                continue;
            }
            let word = line.split_whitespace().next().unwrap_or("");
            if section == "Commands:" && !word.is_empty() && word != "help" {
                let mut next = path.clone();
                next.push(word.to_owned());
                stack.push(next);
            }
            if section == "Options:" {
                for token in line.split_whitespace() {
                    let token = token.trim_end_matches(',');
                    if token.starts_with("--") && token != "--help" {
                        if !manual.contains(token) {
                            missing.push(format!("{path:?} {token}"));
                        }
                        break;
                    }
                }
            }
        }
    }
    for name in text(ok(&["list"], b"")).lines() {
        let name = name.split(' ').nth(1).unwrap();
        // The manual writes the families out with their widths and
        // hashes as patterns; the fixed names must be there verbatim.
        let patterned = name.starts_with("aes-")
            || name.starts_with("ff1-")
            || name.starts_with("ff3-1-")
            || name.starts_with("hmac-")
            || name.starts_with("ecdsa-")
            || name.starts_with("rsa-")
            || name.starts_with("slh-dsa-");
        if !patterned && !manual.contains(name) {
            missing.push(name.to_owned());
        }
    }
    assert!(missing.is_empty(), "not in scytale.1: {missing:#?}");
    // The header names the version, and a release bumps it by hand.
    let version = env!("CARGO_PKG_VERSION");
    let (major_minor, _) = version.rsplit_once('.').unwrap();
    let header = manual.lines().next().unwrap();
    assert!(
        header.contains(&format!("\"scytale {major_minor}\"")),
        "scytale.1 header {header:?} is not for version {version}"
    );
}
