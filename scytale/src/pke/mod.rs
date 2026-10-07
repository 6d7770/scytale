//! Public-key encryption: anyone can encrypt to a public key, and
//! only the holder of the private key can read the result.
//!
//! [`hpke`] (RFC 9180) is the scheme to pick: it encapsulates a
//! fresh secret to the recipient's key and encrypts any amount of
//! data under it. [`rsa`], with OAEP padding, is for the formats that
//! name it; it moves keys, not data, since a message must fit inside
//! one modulus. When both
//! parties are present to contribute a key pair, key agreement under
//! [`kex`](crate::kex) is the better default; public-key encryption
//! is for the recipient who is not online, or the format that asks
//! for it by name.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::pke::rsa::PrivateKey;
//! use scytale::random::CtrDrbg;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::generate(&mut rng, 2048)?;
//!
//! // The sender encrypts a session key to the public half.
//! let session_key = [0x42u8; 32];
//! let sealed = key
//!     .public_key()
//!     .encrypt_oaep::<Sha256, _>(&mut rng, b"", &session_key)?;
//!
//! // The key holder recovers it.
//! let mut out = [0u8; 256];
//! let n = key.decrypt_oaep::<Sha256>(b"", sealed.as_ref(), &mut out)?;
//! assert_eq!(&out[..n], &session_key);
//! # Ok(())
//! # }
//! ```

pub mod hpke;
pub mod rsa;
