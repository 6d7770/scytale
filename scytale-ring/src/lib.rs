//! A drop-in replacement for ring 0.17, implemented with scytale.
//!
//! This crate presents the public interface of
//! [ring](https://crates.io/crates/ring) 0.17, and does the work with
//! [scytale](https://crates.io/crates/scytale). It is not a fork: no
//! line of ring's implementation is here, and there is no C or
//! assembly to build. Code written against ring compiles against it
//! unchanged, because the library is named `ring`.
//!
//! This release presents ring 0.17's API, checked against ring 0.17.14,
//! and is tested with rustls 0.23.45 and rustls-webpki 0.103.15. The
//! version number is this crate's own, not ring's; the README keeps a
//! table of which ring each release presents.
//!
//! Switch a crate over in its own manifest:
//!
//! ```toml
//! [dependencies]
//! ring = { package = "scytale-ring", version = "0.10" }
//! ```
//!
//! That reaches the crate whose manifest it is. It cannot reach a
//! dependency that names ring itself: cargo's `[patch]` matches a
//! replacement by its real package name, which this is not.
//!
//! # Where it differs from ring
//!
//! ECDSA signatures are deterministic here (RFC 6979), where ring
//! draws a random nonce. Both verify against the other, and the
//! random source ring asks for is accepted and not used, but a test
//! that compares signature bytes with stored ones will not match.
//!
//! The minimum Rust is scytale's, 1.88, where ring's is 1.66.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", feature = "test_logging"))]
extern crate std;

mod debug;
mod pkcs8_peek;

/// A vector file for [`test::run`], read at compile time.
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! test_file {
    ($file_name:expr) => {
        $crate::test::File {
            file_name: $file_name,
            contents: include_str!($file_name),
        }
    };
}

pub mod aead;
pub mod agreement;
#[doc(hidden)]
#[deprecated(note = "Will be removed. Internal module not intended for \
                    external use, with no promises regarding side channels.")]
pub mod constant_time;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
pub mod io;
pub mod pbkdf2;
pub mod pkcs8;
pub mod rand;
pub mod rsa;
pub mod signature;
#[cfg(feature = "alloc")]
#[doc(hidden)]
#[deprecated(note = "internal API that will be removed")]
pub mod test;

mod sealed {
    pub trait Sealed {}
}
