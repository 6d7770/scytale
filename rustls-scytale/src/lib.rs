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
//! TLS 1.3:
//!
//! - Cipher suites: AES-128-GCM-SHA256, AES-256-GCM-SHA384 and
//!   ChaCha20-Poly1305-SHA256 by default; AES-128-CCM-SHA256 and
//!   AES-128-CCM-8-SHA256 on request.
//! - QUIC: every suite but AES-128-CCM-8 also protects QUIC packets
//!   and their headers (RFC 9001), so rustls's QUIC support runs on
//!   this provider. RFC 9001 forbids the 8-byte tag in QUIC.
//! - Key exchange: X25519MLKEM768 first, then X25519, P-256 and
//!   P-384. SECP256R1MLKEM768, ML-KEM-768 and ML-KEM-1024 are in
//!   [`ALL_KX_GROUPS`] for a program that asks for them.
//! - Handshake signatures: ML-DSA-44, -65 and -87; ECDSA on P-256,
//!   P-384 and P-521, each with its own hash; Ed25519; RSA-PSS.
//! - Encrypted Client Hello: HPKE with DHKEM over X25519, P-256,
//!   P-384 and P-521, each with its own hash, and AES-128-GCM,
//!   AES-256-GCM and ChaCha20-Poly1305, in [`hpke`].
//!
//! TLS 1.2:
//!
//! - Cipher suites: ECDHE-ECDSA and ECDHE-RSA, each with
//!   AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, by default;
//!   ECDHE-ECDSA with AES-128-CCM, AES-256-CCM, AES-128-CCM-8 and
//!   AES-256-CCM-8 on request.
//! - Key exchange: X25519, P-256 and P-384. The post-quantum groups
//!   are defined for TLS 1.3 only.
//! - Handshake signatures: ECDSA on P-256, P-384 and P-521, where a
//!   peer's may pair any of the curves with SHA-256, SHA-384 or
//!   SHA-512; Ed25519; RSA-PSS and RSA PKCS#1 v1.5.
//!
//! Both:
//!
//! - Certificate verification: ECDSA on P-256, P-384 and P-521 with
//!   SHA-256, SHA-384 or SHA-512; Ed25519; RSA PKCS#1 v1.5 and PSS,
//!   2048 to 8192 bits; ML-DSA.
//! - Private keys: RSA in PKCS#1 or PKCS#8; ECDSA in SEC 1 or
//!   PKCS#8; Ed25519 and ML-DSA in PKCS#8.
//! - Session tickets: sealed with ChaCha20-Poly1305, under a key
//!   rotated every six hours.
//!
//! # AES-CCM
//!
//! The CCM suites are for the constrained-device profiles that ask
//! for them; none is a default. The 16-byte-tag ones are in
//! [`ALL_TLS13_CIPHER_SUITES`] and [`ALL_TLS12_CIPHER_SUITES`]. The
//! CCM-8 ones, whose 8-byte tag lets a forgery succeed with
//! probability 2^-64 a try, are in no list: a program gets one only
//! by naming it in [`cipher_suite`], never by taking a whole list.
//! rustls has no form for CCM keys to be handed to kernel TLS in, so
//! extracting them is refused.
//!
//! Everything is a call into scytale; this crate holds only what
//! rustls asks of a provider: the record layouts, the lists, and the
//! traits between them. It is not FIPS validated, and says so.
//!
//! [`CryptoProvider::get_default`]: rustls::crypto::CryptoProvider::get_default
//! [rustls]: ::rustls
//! [scytale]: ::scytale

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
pub mod hpke;
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
    ML_DSA_44, ML_DSA_65, ML_DSA_87, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS, RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY, SUPPORTED_SIG_ALGS,
};

/// The provider, with the default TLS 1.3 and TLS 1.2 suites and key
/// exchange groups.
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
/// PKCS#8, Ed25519 and ML-DSA in PKCS#8.
pub static DEFAULT_KEY_PROVIDER: &dyn KeyProvider = &sign::Keys;

/// The TLS 1.3 suites a provider uses unless told otherwise, in
/// preference order: AES-128-GCM first, which is fast wherever AES is
/// in hardware and strong enough everywhere.
pub static DEFAULT_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

/// Every TLS 1.3 suite here with a full-length tag: the defaults,
/// then AES-128-CCM. The CCM_8 suite is left out, so that a program
/// taking this whole list does not accept an 8-byte tag unawares;
/// it is in [`cipher_suite`] for a program that names it.
pub static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS13_AES_128_CCM_SHA256,
];

/// The TLS 1.2 suites a provider uses unless told otherwise, in
/// preference order: ECDHE only, AEADs only.
pub static DEFAULT_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Every TLS 1.2 suite here with a full-length tag: the defaults,
/// then ECDHE-ECDSA with AES-128-CCM and AES-256-CCM. The CCM_8
/// suites are left out, as from [`ALL_TLS13_CIPHER_SUITES`].
pub static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
];

/// The cipher suites, one by one, the CCM_8 suites included.
pub mod cipher_suite {
    pub use crate::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM, TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM, TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use crate::tls13::{
        TLS13_AES_128_CCM_8_SHA256, TLS13_AES_128_CCM_SHA256,
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
