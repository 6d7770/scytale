//! Every algorithm name the tool takes, with what each takes: the
//! one place a key, nonce, tag or output length is written down.
//!
//! The dispatch to the library's types is a `match` in each command
//! (a type cannot sit in a table), and a test in each command checks
//! the table against it. The table serves everything else: `list`,
//! the length checks made before any call, and the error messages
//! that say what an algorithm takes.

use crate::fail::{Result, usage};

/// A length an algorithm takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Len {
    /// Exactly this many bytes.
    Exact(usize),
    /// From the first to the second, inclusive.
    Range(usize, usize),
    /// An even count from the first to the second, inclusive.
    Even(usize, usize),
    /// Any length, empty included.
    Any,
    /// Not taken at all.
    None,
}

impl Len {
    /// Whether `n` bytes is a length this allows.
    pub fn allows(self, n: usize) -> bool {
        match self {
            Len::Exact(m) => n == m,
            Len::Range(lo, hi) => (lo..=hi).contains(&n),
            Len::Even(lo, hi) => (lo..=hi).contains(&n) && n.is_multiple_of(2),
            Len::Any => true,
            Len::None => false,
        }
    }

    /// The length as a message says it: "32 bytes", "7 to 13 bytes".
    pub fn describe(self) -> String {
        match self {
            Len::Exact(1) => "1 byte".into(),
            Len::Exact(n) => format!("{n} bytes"),
            Len::Range(lo, hi) => format!("{lo} to {hi} bytes"),
            Len::Even(lo, hi) => {
                format!("an even count from {lo} to {hi} bytes")
            }
            Len::Any => "any length".into(),
            Len::None => "nothing".into(),
        }
    }
}

/// One algorithm: its name and what it takes.
#[derive(Debug)]
pub struct Entry {
    pub name: &'static str,
    /// The key. `Any` for HMAC and KMAC; the modes take the cipher's.
    pub key: Len,
    /// The nonce, IV, counter block or tweak, whichever the algorithm
    /// calls it.
    pub nonce: Len,
    /// The authentication tag.
    pub tag: Len,
    /// What comes out: a digest, a tag, a signature, a secret.
    pub output: Len,
    /// One clause for `list --long` and the messages.
    pub note: &'static str,
}

/// A family of names, as one command takes them. The entries are
/// slices of slices so that a run of names built by a macro sits
/// beside names written out.
pub struct Family {
    /// What `list` calls it.
    pub name: &'static str,
    /// What a message calls one: "hash", "cipher", "signature scheme".
    pub what: &'static str,
    pub entries: &'static [&'static [Entry]],
}

const fn e(
    name: &'static str,
    key: Len,
    nonce: Len,
    tag: Len,
    output: Len,
    note: &'static str,
) -> Entry {
    Entry {
        name,
        key,
        nonce,
        tag,
        output,
        note,
    }
}

use Len::{Any, Even, Exact, None as No, Range};

/// The names of the plain hashes, for the schemes built over one.
pub const HASHES: [&str; 11] = [
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
];

/// The digest lengths of [`HASHES`], in order.
const DIGESTS: [usize; 11] = [20, 28, 32, 48, 64, 28, 32, 28, 32, 48, 64];

/// The digest length of a plain hash.
pub fn digest_len(hash: &str) -> Option<usize> {
    HASHES.iter().position(|&h| h == hash).map(|i| DIGESTS[i])
}

/// Eleven entries, one per hash, named `$prefix` and the hash; the
/// output is the digest length where `$digest` says so.
macro_rules! over_hashes {
    ($p:literal, $k:expr, $out:ident, $n:literal) => {
        [
            e(concat!($p, "sha1"), $k, No, No, $out(20), $n),
            e(concat!($p, "sha224"), $k, No, No, $out(28), $n),
            e(concat!($p, "sha256"), $k, No, No, $out(32), $n),
            e(concat!($p, "sha384"), $k, No, No, $out(48), $n),
            e(concat!($p, "sha512"), $k, No, No, $out(64), $n),
            e(concat!($p, "sha512-224"), $k, No, No, $out(28), $n),
            e(concat!($p, "sha512-256"), $k, No, No, $out(32), $n),
            e(concat!($p, "sha3-224"), $k, No, No, $out(28), $n),
            e(concat!($p, "sha3-256"), $k, No, No, $out(32), $n),
            e(concat!($p, "sha3-384"), $k, No, No, $out(48), $n),
            e(concat!($p, "sha3-512"), $k, No, No, $out(64), $n),
        ]
    };
}

/// The digest length, for a hash or a MAC over one.
const fn exact(n: usize) -> Len {
    Exact(n)
}

/// Any length, for a scheme whose output the key sizes.
const fn any(_: usize) -> Len {
    Any
}

static PLAIN_HASHES: [Entry; 11] = over_hashes!("", No, exact, "");

static XOFS: [Entry; 4] = [
    e("shake128", No, No, No, Any, "--length required"),
    e("shake256", No, No, No, Any, "--length required"),
    e(
        "cshake128",
        No,
        No,
        No,
        Any,
        "--length; --function-name, --customization",
    ),
    e(
        "cshake256",
        No,
        No,
        No,
        Any,
        "--length; --function-name, --customization",
    ),
];

pub static HASH: Family = Family {
    name: "hash",
    what: "hash",
    entries: &[&PLAIN_HASHES, &XOFS],
};

static HMAC: [Entry; 11] =
    over_hashes!("hmac-", Any, exact, "a key of any length");

static OTHER_MACS: [Entry; 6] = [
    e("cmac-aes-128", Exact(16), No, No, Exact(16), ""),
    e("cmac-aes-192", Exact(24), No, No, Exact(16), ""),
    e("cmac-aes-256", Exact(32), No, No, Exact(16), ""),
    e(
        "kmac128",
        Any,
        No,
        No,
        Any,
        "--length, 32 without it; --customization",
    ),
    e(
        "kmac256",
        Any,
        No,
        No,
        Any,
        "--length, 64 without it; --customization",
    ),
    e(
        "poly1305",
        Exact(32),
        No,
        No,
        Exact(16),
        "one key per message",
    ),
];

pub static MAC: Family = Family {
    name: "mac",
    what: "MAC",
    entries: &[&HMAC, &OTHER_MACS],
};

static AEADS: [Entry; 12] = [
    e(
        "aes-128-gcm",
        Exact(16),
        Range(1, 65535),
        Range(4, 16),
        No,
        "",
    ),
    e(
        "aes-192-gcm",
        Exact(24),
        Range(1, 65535),
        Range(4, 16),
        No,
        "",
    ),
    e(
        "aes-256-gcm",
        Exact(32),
        Range(1, 65535),
        Range(4, 16),
        No,
        "",
    ),
    e(
        "aes-128-gcm-siv",
        Exact(16),
        Exact(12),
        Exact(16),
        No,
        "nonce misuse resistant",
    ),
    e(
        "aes-256-gcm-siv",
        Exact(32),
        Exact(12),
        Exact(16),
        No,
        "nonce misuse resistant",
    ),
    e("aes-128-ccm", Exact(16), Range(7, 13), Even(4, 16), No, ""),
    e("aes-192-ccm", Exact(24), Range(7, 13), Even(4, 16), No, ""),
    e("aes-256-ccm", Exact(32), Range(7, 13), Even(4, 16), No, ""),
    e(
        "aes-128-xpn",
        Exact(16),
        Exact(24),
        Range(4, 16),
        No,
        "nonce is salt || frame",
    ),
    e(
        "aes-192-xpn",
        Exact(24),
        Exact(24),
        Range(4, 16),
        No,
        "nonce is salt || frame",
    ),
    e(
        "aes-256-xpn",
        Exact(32),
        Exact(24),
        Range(4, 16),
        No,
        "nonce is salt || frame",
    ),
    e("chacha20-poly1305", Exact(32), Exact(12), Exact(16), No, ""),
];

pub static AEAD: Family = Family {
    name: "aead",
    what: "AEAD",
    entries: &[&AEADS],
};

/// Three entries, one per AES width, for one mode.
macro_rules! aes_mode {
    ($mode:literal, $nonce:expr, $note:literal) => {
        [
            e(concat!("aes-128-", $mode), Exact(16), $nonce, No, No, $note),
            e(concat!("aes-192-", $mode), Exact(24), $nonce, No, No, $note),
            e(concat!("aes-256-", $mode), Exact(32), $nonce, No, No, $note),
        ]
    };
}

static ECB: [Entry; 3] = aes_mode!("ecb", No, "whole blocks; --padding");
static CBC: [Entry; 3] =
    aes_mode!("cbc", Exact(16), "--iv; whole blocks; --padding");
static CTR: [Entry; 3] =
    aes_mode!("ctr", Exact(16), "--iv, the first counter block");
static CFB1: [Entry; 3] = aes_mode!("cfb1", Exact(16), "--iv");
static CFB8: [Entry; 3] = aes_mode!("cfb8", Exact(16), "--iv");
static CFB128: [Entry; 3] =
    aes_mode!("cfb128", Exact(16), "--iv; whole blocks; --padding");
static OFB: [Entry; 3] = aes_mode!("ofb", Exact(16), "--iv");
static XTS: [Entry; 3] =
    aes_mode!("xts", Exact(16), "--iv, the tweak; --tweak-key; one sector");
static KW: [Entry; 3] =
    aes_mode!("kw", No, "cipher wrap; whole 8-byte blocks, two or more");
static KWP: [Entry; 3] = aes_mode!("kwp", No, "cipher wrap; any length");
static CHACHA20: [Entry; 1] = [e(
    "chacha20",
    Exact(32),
    Exact(12),
    No,
    No,
    "--nonce; --counter",
)];
static FF1: [Entry; 3] = [
    e(
        "ff1-aes-128",
        Exact(16),
        No,
        No,
        No,
        "--alphabet; --tweak, any length",
    ),
    e(
        "ff1-aes-192",
        Exact(24),
        No,
        No,
        No,
        "--alphabet; --tweak, any length",
    ),
    e(
        "ff1-aes-256",
        Exact(32),
        No,
        No,
        No,
        "--alphabet; --tweak, any length",
    ),
];
static FF3_1: [Entry; 3] = [
    e(
        "ff3-1-aes-128",
        Exact(16),
        No,
        No,
        No,
        "--alphabet; --tweak, 7 bytes",
    ),
    e(
        "ff3-1-aes-192",
        Exact(24),
        No,
        No,
        No,
        "--alphabet; --tweak, 7 bytes",
    ),
    e(
        "ff3-1-aes-256",
        Exact(32),
        No,
        No,
        No,
        "--alphabet; --tweak, 7 bytes",
    ),
];

pub static CIPHER: Family = Family {
    name: "cipher",
    what: "cipher",
    entries: &[
        &ECB, &CBC, &CTR, &CFB1, &CFB8, &CFB128, &OFB, &XTS, &KW, &KWP,
        &CHACHA20, &FF1, &FF3_1,
    ],
};

static KDF_HASHES: [Entry; 11] =
    over_hashes!("", Any, any, "hkdf, pbkdf2 or tls12 over this hash");

pub static KDF: Family = Family {
    name: "kdf",
    what: "hash",
    entries: &[&KDF_HASHES],
};

static KEYS: [Entry; 29] = [
    e("ed25519", No, No, No, No, "signatures"),
    e("x25519", No, No, No, No, "key agreement"),
    e(
        "ecdsa-p256",
        No,
        No,
        No,
        No,
        "signatures; serves ecdh-p256 too",
    ),
    e(
        "ecdsa-p384",
        No,
        No,
        No,
        No,
        "signatures; serves ecdh-p384 too",
    ),
    e(
        "ecdsa-p521",
        No,
        No,
        No,
        No,
        "signatures; serves ecdh-p521 too",
    ),
    e(
        "ecdh-p256",
        No,
        No,
        No,
        No,
        "key agreement; the same key as ecdsa-p256",
    ),
    e(
        "ecdh-p384",
        No,
        No,
        No,
        No,
        "key agreement; the same key as ecdsa-p384",
    ),
    e(
        "ecdh-p521",
        No,
        No,
        No,
        No,
        "key agreement; the same key as ecdsa-p521",
    ),
    e(
        "rsa-2048",
        No,
        No,
        No,
        No,
        "rsa-N for any N from 1024 to 8192",
    ),
    e("rsa-3072", No, No, No, No, "signatures and encryption"),
    e("rsa-4096", No, No, No, No, "signatures and encryption"),
    e("ml-kem-512", No, No, No, No, "key encapsulation"),
    e("ml-kem-768", No, No, No, No, "key encapsulation"),
    e("ml-kem-1024", No, No, No, No, "key encapsulation"),
    e("ml-dsa-44", No, No, No, No, "signatures"),
    e("ml-dsa-65", No, No, No, No, "signatures"),
    e("ml-dsa-87", No, No, No, No, "signatures"),
    e("slh-dsa-sha2-128s", No, No, No, No, "signatures"),
    e("slh-dsa-sha2-128f", No, No, No, No, "signatures"),
    e("slh-dsa-sha2-192s", No, No, No, No, "signatures"),
    e("slh-dsa-sha2-192f", No, No, No, No, "signatures"),
    e("slh-dsa-sha2-256s", No, No, No, No, "signatures"),
    e("slh-dsa-sha2-256f", No, No, No, No, "signatures"),
    e("slh-dsa-shake-128s", No, No, No, No, "signatures"),
    e("slh-dsa-shake-128f", No, No, No, No, "signatures"),
    e("slh-dsa-shake-192s", No, No, No, No, "signatures"),
    e("slh-dsa-shake-192f", No, No, No, No, "signatures"),
    e("slh-dsa-shake-256s", No, No, No, No, "signatures"),
    e("slh-dsa-shake-256f", No, No, No, No, "signatures"),
];

pub static KEY: Family = Family {
    name: "key",
    what: "key algorithm",
    entries: &[&KEYS],
};

static ED25519: [Entry; 1] = [e(
    "ed25519",
    No,
    No,
    No,
    Exact(64),
    "an Ed25519 key; --context",
)];
static ECDSA: [Entry; 11] =
    over_hashes!("ecdsa-", No, any, "a P-256, P-384 or P-521 key; DER out");
static RSA_PSS: [Entry; 11] =
    over_hashes!("rsa-pss-", No, any, "an RSA or RSA-PSS key");
static RSA_PKCS1: [Entry; 11] =
    over_hashes!("rsa-pkcs1-", No, any, "an RSA key");
static PQ_SIGS: [Entry; 15] = [
    e("ml-dsa-44", No, No, No, Exact(2420), "--context"),
    e("ml-dsa-65", No, No, No, Exact(3309), "--context"),
    e("ml-dsa-87", No, No, No, Exact(4627), "--context"),
    e("slh-dsa-sha2-128s", No, No, No, Exact(7856), "--context"),
    e("slh-dsa-sha2-128f", No, No, No, Exact(17088), "--context"),
    e("slh-dsa-sha2-192s", No, No, No, Exact(16224), "--context"),
    e("slh-dsa-sha2-192f", No, No, No, Exact(35664), "--context"),
    e("slh-dsa-sha2-256s", No, No, No, Exact(29792), "--context"),
    e("slh-dsa-sha2-256f", No, No, No, Exact(49856), "--context"),
    e("slh-dsa-shake-128s", No, No, No, Exact(7856), "--context"),
    e("slh-dsa-shake-128f", No, No, No, Exact(17088), "--context"),
    e("slh-dsa-shake-192s", No, No, No, Exact(16224), "--context"),
    e("slh-dsa-shake-192f", No, No, No, Exact(35664), "--context"),
    e("slh-dsa-shake-256s", No, No, No, Exact(29792), "--context"),
    e("slh-dsa-shake-256f", No, No, No, Exact(49856), "--context"),
];

pub static SIG: Family = Family {
    name: "sig",
    what: "signature scheme",
    entries: &[&ED25519, &ECDSA, &RSA_PSS, &RSA_PKCS1, &PQ_SIGS],
};

static KEXS: [Entry; 4] = [
    e("x25519", No, No, No, Exact(32), "X25519 keys"),
    e("ecdh-p256", No, No, No, Exact(32), "P-256 keys"),
    e("ecdh-p384", No, No, No, Exact(48), "P-384 keys"),
    e("ecdh-p521", No, No, No, Exact(66), "P-521 keys"),
];

pub static KEX: Family = Family {
    name: "kex",
    what: "key agreement",
    entries: &[&KEXS],
};

static KEMS: [Entry; 3] = [
    e("ml-kem-512", No, No, No, Exact(32), "768-byte ciphertext"),
    e("ml-kem-768", No, No, No, Exact(32), "1088-byte ciphertext"),
    e("ml-kem-1024", No, No, No, Exact(32), "1568-byte ciphertext"),
];

pub static KEM: Family = Family {
    name: "kem",
    what: "KEM",
    entries: &[&KEMS],
};

static OAEP: [Entry; 11] =
    over_hashes!("rsa-oaep-", No, any, "an RSA key; --label");

pub static PKE: Family = Family {
    name: "pke",
    what: "encryption scheme",
    entries: &[&OAEP],
};

/// Every family, in the order `list` prints them.
pub static FAMILIES: [&Family; 10] = [
    &HASH, &MAC, &AEAD, &CIPHER, &KDF, &KEY, &SIG, &KEX, &KEM, &PKE,
];

impl Family {
    /// The entries, in order.
    pub fn iter(&self) -> impl Iterator<Item = &'static Entry> {
        self.entries.iter().flat_map(|run| run.iter())
    }

    /// The entry `name` names, with `_` and `-` and case
    /// interchangeable; otherwise a message naming the nearest.
    pub fn find(&self, name: &str) -> Result<&'static Entry> {
        let wanted = normalise(name);
        if let Some(entry) = self.iter().find(|e| e.name == wanted) {
            return Ok(entry);
        }
        let near = self.nearest(&wanted);
        let mut hint = if near.is_empty() {
            String::new()
        } else {
            format!("; did you mean {}?", near.join(", "))
        };
        // A file where the algorithm should be is the algorithm left
        // out, as the old command line allowed.
        if std::path::Path::new(name).is_file() {
            hint.push_str(&format!(
                "; \"{name}\" is a file, and the {} comes before it",
                self.what
            ));
        }
        Err(usage!(
            "no {} named \"{name}\"{hint} (scytale list {})",
            self.what,
            self.name
        ))
    }

    /// Up to three names within a small edit distance of `wanted`,
    /// or sharing a start with it, nearest first.
    fn nearest(&self, wanted: &str) -> Vec<&'static str> {
        let mut scored: Vec<(usize, &'static str)> = self
            .iter()
            .filter_map(|e| {
                let d = distance(wanted, e.name);
                // Close by edit distance, by one being the start of
                // the other, or by every word of the wanted name
                // being a word of this one: "aes-gcm" for the three
                // aes-*-gcm.
                let words = |s: &str| {
                    s.split('-').map(str::to_owned).collect::<Vec<_>>()
                };
                let mine = words(e.name);
                let close = d <= 3
                    || e.name.starts_with(wanted)
                    || wanted.starts_with(e.name)
                    || words(wanted).iter().all(|w| mine.contains(w));
                close.then_some((d, e.name))
            })
            .collect();
        scored.sort();
        scored.truncate(3);
        scored.into_iter().map(|(_, n)| n).collect()
    }
}

fn normalise(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

/// Levenshtein distance, for the suggestions.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_suggests() {
        assert_eq!(HASH.find("sha256").unwrap().name, "sha256");
        assert_eq!(HASH.find(" SHA3_256 ").unwrap().name, "sha3-256");
        let err = HASH.find("sha-256").unwrap_err().to_string();
        assert!(err.contains("did you mean sha256"), "{err}");
        assert!(err.contains("scytale list hash"), "{err}");
        let err = AEAD.find("aes-gcm").unwrap_err().to_string();
        assert!(err.contains("aes-128-gcm"), "{err}");
        let err = CIPHER.find("blowfish").unwrap_err().to_string();
        assert!(!err.contains("did you mean"), "{err}");
        assert!(err.starts_with("no cipher named \"blowfish\""), "{err}");
    }

    #[test]
    fn every_table_is_filled_and_unique() {
        for family in FAMILIES {
            let mut seen = std::collections::HashSet::new();
            for entry in family.iter() {
                assert!(!entry.name.is_empty(), "{}", family.name);
                let fresh = seen.insert(entry.name);
                assert!(fresh, "{}: {} twice", family.name, entry.name);
            }
        }
        assert_eq!(SIG.iter().count(), 49);
        assert_eq!(CIPHER.iter().count(), 37);
    }

    #[test]
    fn lengths() {
        assert!(Exact(3).allows(3) && !Exact(3).allows(4));
        assert!(Range(7, 13).allows(7) && !Range(7, 13).allows(14));
        assert!(Even(4, 16).allows(16) && !Even(4, 16).allows(15));
        assert!(Any.allows(0) && !No.allows(0));
        assert_eq!(Exact(32).describe(), "32 bytes");
        assert_eq!(Exact(1).describe(), "1 byte");
        assert_eq!(Range(7, 13).describe(), "7 to 13 bytes");
        assert_eq!(digest_len("sha384"), Some(48));
        assert_eq!(digest_len("shake128"), None);
    }
}
