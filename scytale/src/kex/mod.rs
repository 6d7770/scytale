//! Key agreement: both parties contribute a key pair and derive the
//! same secret, one that neither of them chose.
//!
//! [`x25519`] is the scheme to pick unless a protocol names another;
//! [`ecdh`] over P-256, P-384 and P-521 covers the protocols and
//! certificates that ask for the NIST curves by name. When one side
//! must instead pick the secret and encrypt it to the other, that is
//! public-key
//! encryption, under [`pke`](crate::pke); when the post-quantum
//! encapsulation schemes land they will sit beside these in a
//! module of their own.
//!
//! A shared secret from key agreement is a curve point, not a key:
//! run it through [`hkdf`](crate::kdf::hkdf) and use the output.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::hkdf;
//! use scytale::kex::x25519;
//! use scytale::random::CtrDrbg;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//!
//! // Each party publishes one value and keeps one.
//! let alice = x25519::PrivateKey::generate(&mut rng)?;
//! let bob = x25519::PrivateKey::generate(&mut rng)?;
//! let shared = alice.shared_secret(bob.public_key())?;
//! let mut key = [0u8; 32];
//! hkdf::derive::<Sha256>(b"", &shared, &[b"session v1"], &mut key)?;
//! # Ok(())
//! # }
//! ```

pub mod ecdh;
pub mod x25519;
