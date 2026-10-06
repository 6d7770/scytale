//! Randomness for rustls, and for the key generation behind it.

use rustls::crypto::{GetRandomFailed, SecureRandom};
use scytale::random::{CtrDrbg, MAX_REQUEST};
use scytale::{Error, Random as _};

/// The provider's random source: a generator built for each request
/// from the system's entropy.
///
/// A generator kept between calls would need a lock, and would be
/// copied along with the process by a `fork` or a virtual machine
/// snapshot, after which two processes hand out the same bytes. One
/// that lives for a single call cannot outlive the state it was
/// seeded in.
#[derive(Debug)]
pub(crate) struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        fill(buf).map_err(|_| GetRandomFailed)
    }
}

/// Fills `buf` from a fresh generator.
pub(crate) fn fill(buf: &mut [u8]) -> Result<(), Error> {
    let mut rng = generator()?;
    // One request is at most `MAX_REQUEST` bytes; nothing in TLS
    // asks for more, but nothing here assumes it.
    for chunk in buf.chunks_mut(MAX_REQUEST) {
        rng.fill(chunk)?;
    }
    Ok(())
}

/// A fresh generator, for the scytale calls that take one: key
/// generation, encapsulation, signing salts.
pub(crate) fn generator() -> Result<CtrDrbg, Error> {
    CtrDrbg::from_system()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Random.fill(&mut a).unwrap();
        Random.fill(&mut b).unwrap();
        // Equal by chance once in 2^256.
        assert_ne!(a, b);
    }

    #[test]
    fn fills_more_than_one_request() {
        let mut buf = alloc::vec![0u8; MAX_REQUEST + 17];
        fill(&mut buf).unwrap();
        // The tail is filled too: 17 zero bytes by chance is 2^-136.
        assert_ne!(buf[MAX_REQUEST..], [0u8; 17]);
    }
}
