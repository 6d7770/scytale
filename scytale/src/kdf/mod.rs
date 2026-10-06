//! Key derivation functions.
//!
//! Two different jobs share the name. [`hkdf`] turns keying material
//! that is already unguessable, such as a shared secret from a key
//! agreement, into as many keys as a protocol needs. [`pbkdf2`]
//! turns a password, which is guessable, into a key, and its
//! iteration count is there to make each guess cost the attacker
//! what it costs you. [`tls12`] is the first job as TLS 1.2 defined
//! it, for the implementations that still speak that version.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::{hkdf, pbkdf2};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! // A shared secret from a key agreement: already unguessable, so
//! // one hash's worth of work turns it into keys.
//! let shared_secret = [0x5a; 32];
//! let mut keys = [0u8; 64];
//! let salt = b"session salt";
//! hkdf::derive::<Sha256>(salt, &shared_secret, &[b"app v1"], &mut keys)?;
//! let (encrypt_key, mac_key) = keys.split_at(32);
//!
//! // A password: guessable, so every guess must be made expensive.
//! let mut key = [0u8; 32];
//! let salt = b"per-user salt";
//! pbkdf2::pbkdf2::<Sha256>(b"correct horse", salt, 600_000, &mut key)?;
//! # let _ = (encrypt_key, mac_key);
//! # Ok(())
//! # }
//! ```
//!
//! If the input came from a human, use `pbkdf2`; if it came from a
//! machine, use `hkdf`. Running HKDF over a password gives a key that
//! is exactly as guessable as the password was.

pub mod hkdf;
pub mod pbkdf2;
pub mod tls12;
