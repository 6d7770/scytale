//! Portable cryptographic primitives.
//!
//! Symmetric ciphers, authenticated encryption and the modes over
//! them, hashes, message authentication, key derivation, key
//! agreement, public-key encryption, signatures and random numbers,
//! written to run anywhere Rust
//! does: `no_std`, no allocator, no cargo features to get wrong. Where
//! the processor has instructions for a primitive they are used,
//! chosen at run time, and there is always portable code behind them.
//!
//! | Module | What is in it |
//! | --- | --- |
//! | [`aead`] | GCM, GCM-SIV, XPN, CCM and ChaCha20-Poly1305 |
//! | [`cipher`] | AES, ChaCha20, and the modes built on them |
//! | [`hash`] | SHA-2, SHA-3, SHAKE, cSHAKE, and SHA-1 for old protocols |
//! | [`mac`] | HMAC, CMAC, KMAC and Poly1305 |
//! | [`kdf`] | HKDF, PBKDF2 and the TLS 1.2 PRF |
//! | [`kem`] | ML-KEM key encapsulation |
//! | [`kex`] | X25519 and ECDH key agreement |
//! | [`pke`] | RSA-OAEP public-key encryption |
//! | [`random`] | a CTR_DRBG generator and the entropy that seeds it |
//! | [`constant_time`] | comparing secrets without timing them |
//! | [`codec`] | hex, base64 and PEM, in constant time |
//! | [`sig`] | Ed25519, ECDSA, ML-DSA, SLH-DSA and RSA signatures |
//! | [`KeyInfo`] | which algorithm an encoded key is for |
//! | [`Error`] | the one type every fallible call returns |
//!
//! # Example
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::hash::Hash;
//! use scytale::kdf::hkdf;
//! use scytale::mac::hmac::{Hmac, HmacSha256};
//! use scytale::KeyType;
//! use scytale::cipher::aes::Aes128;
//! use scytale::cipher::Nonces;
//! use scytale::aead::{Aead, Gcm};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // A session key, and a key for each job derived from it,
//! // straight into keys that wipe themselves when they go out of
//! // scope.
//! let secret = [0x42u8; 32];
//! let mut cipher_key = Aes128::zero_key();
//! let mut mac_key = HmacSha256::zero_key();
//! let cipher = &[b"cipher".as_slice()];
//! hkdf::derive::<Sha256>(b"salt", &secret, cipher, cipher_key.as_mut())?;
//! let mac = &[b"mac".as_slice()];
//! hkdf::derive::<Sha256>(b"salt", &secret, mac, mac_key.as_mut())?;
//!
//! // Authenticated encryption, with nonces that cannot repeat.
//! let gcm = Gcm::<Aes128>::new(&cipher_key);
//! let mut nonces =
//!     Nonces::<[u8; 12]>::try_new(&7u64.to_be_bytes(), 0)?;
//! let nonce = nonces.take()?;
//! let mut message = *b"attack at dawn";
//! let mut tag = [0u8; 16];
//! gcm.encrypt(&nonce, b"header", &mut message, &mut tag)?;
//! gcm.decrypt(&nonce, b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"attack at dawn");
//!
//! // A digest, and a tag over the same bytes.
//! let digest = Sha256::digest(&message);
//! let mac = Hmac::<Sha256>::mac(mac_key.as_ref(), &message);
//! assert_ne!(digest, mac);
//! # Ok(())
//! # }
//! ```
//!
//! # Guarantees
//!
//! These hold everywhere in the crate, so they need not be checked
//! primitive by primitive.
//!
//! - Every fallible call returns [`Error`], and no error says anything
//!   about a secret.
//! - A message that fails authentication is wiped before the error is
//!   returned, so unauthenticated plaintext is never handed back by a
//!   one-shot call. The incremental decryptors say so where they
//!   cannot promise this.
//! - Keys, and every state derived from one, are zeroed when dropped.
//! - Tags are compared in time that depends on their length and on
//!   nothing else.
//! - The implementation chosen at run time is never one that leaks
//!   through the cache; table-driven code exists as a peer of the
//!   constant-time code, and must be asked for by name.
//! - `Debug` output never contains key material, so a state can be
//!   logged.
//! - A trait describing a value you hold, a hash, a MAC or a cipher,
//!   has no associated constants and is usable as a trait object once
//!   its types are named: `&mut dyn Hash<Output = [u8; 32]>`. Sizes
//!   are types, [`Block`](BlockType::Block) and [`Key`](KeyType::Key)
//!   among them, so a wrong length is a compile error. Only
//!   construction needs the concrete type.
//!
//! # Non-goals
//!
//! No protocols: TLS, SSH and their kin are built on these pieces,
//! not in here. No allocator, so every output goes into a buffer the
//! caller supplies. The
//! format-preserving modes, [`Ff1`](cipher::mode::Ff1) and
//! [`Ff3_1`](cipher::mode::Ff3_1), are not constant time, and say
//! so. The raw RSA primitives are offered, for building a scheme the
//! crate does not have and for the component test suites, but they
//! pad and check nothing and say so at length.
//!
//! # Rust version
//!
//! Rust 1.88 or later, as `rust-version` in `Cargo.toml` records.

#![no_std]
// Hardware implementations need intrinsics; they opt in per module.
#![deny(unsafe_code)]
// `chunks_exact(N)` reads better than `as_chunks::<N>()` and the
// compiler removes the length checks either way.
#![allow(clippy::chunks_exact_to_as_chunks)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// The vector suites in `acvp` read files and parse JSON, so the
// library's own test build has the standard library; nothing else
// does.
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod acvp;

// The benchmark times a thread by its processor clock, and wasm has
// no such clock to read. It measures rather than checks, so the
// tests there lose nothing by its absence.
#[cfg(all(test, not(target_family = "wasm")))]
mod bench;

pub mod aead;
mod align;
mod arch;
pub mod cipher;
pub mod codec;
pub mod constant_time;
mod der;
mod error;
pub mod hash;
mod implementation;
pub mod kdf;
pub mod kem;
pub mod kex;
mod key_info;
pub mod mac;
mod math;
pub mod pke;
mod probe;
pub mod random;
pub mod sig;

mod traits;

pub use der::Pkcs8Form;
pub use error::Error;
pub use key_info::{Algorithm, KeyInfo};
pub use traits::{BlockType, ByteArray, Key, KeyType, Random};
