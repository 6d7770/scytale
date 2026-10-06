//! Signatures: made with a secret key, checked with a public one.
//!
//! A signature binds a message to the holder of a key. [`ed25519`]
//! is the scheme to pick unless a protocol names another; [`ecdsa`]
//! over P-256, P-384 and P-521 and [`rsa`] with PSS and PKCS#1 v1.5
//! padding cover the protocols and certificates that ask for them by
//! name;
//! [`ml_dsa`] is the post-quantum choice, with keys and signatures
//! of a few kilobytes, and [`slh_dsa`] the conservative one, resting
//! on hashes alone at the price of signatures ten times larger.
//!
//! ```
//! use scytale::random::CtrDrbg;
//! use scytale::sig::ed25519::{PrivateKey, PublicKey};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::generate(&mut rng)?;
//!
//! // Made with the secret, checked with the public.
//! let signature = key.sign(b"release v1.2");
//! let public = key.public_key();
//! public.verify(b"release v1.2", &signature)?;
//! assert!(public.verify(b"release v1.3", &signature).is_err());
//!
//! // The public key in the form other software reads.
//! let pem = public.pem_bytes();
//! assert_eq!(&PublicKey::try_from_pem(&pem)?, public);
//! # Ok(())
//! # }
//! ```

pub mod ecdsa;
pub mod ed25519;
pub mod ml_dsa;
pub mod rsa;
pub mod slh_dsa;
