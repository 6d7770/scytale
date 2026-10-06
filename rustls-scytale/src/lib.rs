//! A [rustls] crypto provider implemented with [scytale]: pure Rust,
//! no C compiler, no build script, and post-quantum key exchange by
//! default.
//!
//! rustls 0.24 carries no cryptography of its own. A program names a
//! provider and hands it to the configuration it builds:
//!
//! ```
//! use std::sync::Arc;
//!
//! # fn main() -> Result<(), rustls::Error> {
//! let provider = Arc::new(rustls_scytale::DEFAULT_PROVIDER);
//! let config = rustls::ClientConfig::builder(provider)
//!     .with_root_certificates(rustls::RootCertStore::empty())
//!     .with_no_client_auth()?;
//! # let _ = config;
//! # Ok(())
//! # }
//! ```
//!
//! or installs it once as the process default, for libraries that
//! build their own configurations from [`CryptoProvider::get_default`]:
//!
//! ```
//! # fn main() {
//! let _ = rustls_scytale::DEFAULT_PROVIDER.install_default();
//! # }
//! ```
//!
//! # What it offers
//!
//! - TLS 1.3: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
//! - TLS 1.2: ECDHE-ECDSA and ECDHE-RSA with the same three.
//! - Key exchange: X25519MLKEM768 first, then X25519, P-256, P-384;
//!   also SECP256R1MLKEM768, ML-KEM-768 and ML-KEM-1024.
//! - Signatures: ECDSA on P-256, P-384 and P-521; Ed25519; RSA-PSS
//!   and PKCS#1 v1.5, 2048 to 8192 bits.
//! - QUIC: packet and header protection for every TLS 1.3 suite.
//! - Session tickets: ChaCha20-Poly1305, the key rotated every six
//!   hours.
//!
//! Everything is a call into scytale; this crate holds only what
//! rustls asks of a provider: the record layouts, the lists, and the
//! traits between them. It is not FIPS validated, and says so.
//!
//! [`CryptoProvider::get_default`]: rustls::crypto::CryptoProvider::get_default
//! [rustls]: https://docs.rs/rustls
//! [scytale]: https://docs.rs/scytale

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::borrow::Cow;

use rustls::crypto::kx::SupportedKxGroup;
use rustls::crypto::{CryptoProvider, KeyProvider, SecureRandom};
use rustls::{Tls12CipherSuite, Tls13CipherSuite};

mod aead;
mod hash;
mod hkdf;
mod kx;
mod prf;
mod quic;
mod random;
mod sign;
mod ticketer;
mod tls12;
mod tls13;
mod verify;

pub use verify::{
    ALL_VERIFICATION_ALGS, ECDSA_P256_SHA256, ECDSA_P256_SHA384,
    ECDSA_P256_SHA512, ECDSA_P384_SHA256, ECDSA_P384_SHA384, ECDSA_P384_SHA512,
    ECDSA_P521_SHA256, ECDSA_P521_SHA384, ECDSA_P521_SHA512, ED25519,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY, SUPPORTED_SIG_ALGS,
};

/// The provider, with every TLS 1.3 and TLS 1.2 suite and the
/// default key exchange groups.
pub const DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(DEFAULT_TLS12_CIPHER_SUITES),
    tls13_cipher_suites: Cow::Borrowed(DEFAULT_TLS13_CIPHER_SUITES),
    kx_groups: Cow::Borrowed(DEFAULT_KX_GROUPS),
    signature_verification_algorithms: SUPPORTED_SIG_ALGS,
    secure_random: DEFAULT_SECURE_RANDOM,
    key_provider: DEFAULT_KEY_PROVIDER,
    ticketer_factory: &ticketer::Tickets,
};

/// The provider with TLS 1.3 only.
pub const DEFAULT_TLS13_PROVIDER: CryptoProvider = CryptoProvider {
    tls12_cipher_suites: Cow::Borrowed(&[]),
    ..DEFAULT_PROVIDER
};

/// The provider with TLS 1.2 only.
pub const DEFAULT_TLS12_PROVIDER: CryptoProvider = CryptoProvider {
    tls13_cipher_suites: Cow::Borrowed(&[]),
    ..DEFAULT_PROVIDER
};

/// The random source: a CTR_DRBG built from the system's entropy for
/// each request.
pub static DEFAULT_SECURE_RANDOM: &dyn SecureRandom = &random::Random;

/// The key loader: RSA in PKCS#1 or PKCS#8, ECDSA keys in SEC 1 or
/// PKCS#8, Ed25519 in PKCS#8.
pub static DEFAULT_KEY_PROVIDER: &dyn KeyProvider = &sign::Keys;

/// The TLS 1.3 suites, in preference order.
pub static DEFAULT_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] =
    ALL_TLS13_CIPHER_SUITES;

/// Every TLS 1.3 suite here: AES-128-GCM first, which is fast
/// wherever AES is in hardware and strong enough everywhere.
pub static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

/// The TLS 1.2 suites, in preference order.
pub static DEFAULT_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] =
    ALL_TLS12_CIPHER_SUITES;

/// Every TLS 1.2 suite here: ECDHE only, AEADs only.
pub static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The cipher suites, one by one.
pub mod cipher_suite {
    pub use crate::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use crate::tls13::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
    };
}

/// The key exchange groups, one by one.
pub mod kx_group {
    pub use crate::kx::{
        MLKEM768, MLKEM1024, SECP256R1, SECP256R1MLKEM768, SECP384R1, X25519,
        X25519MLKEM768,
    };
}

/// The key exchange groups offered by default, in preference order.
///
/// The hybrid comes first, so a client's first key share protects
/// the session against a future quantum computer as well as today's
/// attacks. X25519 follows it, which lets rustls send it alongside
/// as a fallback for a server without the hybrid, and serves TLS
/// 1.2, where no post-quantum group exists.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
];

/// Every key exchange group here. ML-KEM alone is not a default:
/// the hybrids keep a classical group under it in case ML-KEM falls.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::SECP256R1MLKEM768,
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
    kx_group::MLKEM768,
    kx_group::MLKEM1024,
];
