//! Session tickets: the server's resumption state, sealed so that
//! only the server can read it back.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use rustls::Error;
use rustls::TicketRotator;
use rustls::crypto::{TicketProducer, TicketerFactory};
use scytale::constant_time;

use crate::aead::{Algorithm, NONCE_LEN, SealingKey, TAG_LEN};
use crate::random;

/// How long one ticket key is used before a new one replaces it.
/// The rotator accepts tickets under the key before, so a ticket
/// lives at most twice this; RFC 8446 allows a week, and a shorter
/// life limits what a stolen key can open.
const LIFETIME: Duration = Duration::from_secs(6 * 60 * 60);

/// Names the key a ticket was sealed under, so a ticket from another
/// key is turned away before any decryption is tried.
const KEY_NAME_LEN: usize = 16;

/// The ticketer factory.
#[derive(Debug)]
pub(crate) struct Tickets;

impl TicketerFactory for Tickets {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        Ok(Arc::new(TicketRotator::new(LIFETIME, Ticketer::new)?))
    }
}

/// One ticket key, under ChaCha20-Poly1305. A ticket is
/// `key name || nonce || ciphertext || tag`, the key name also the
/// associated data, and the nonce random: a counter would tell anyone
/// holding two tickets how many were issued between them.
struct Ticketer {
    key: SealingKey,
    key_name: [u8; KEY_NAME_LEN],
    /// The longest ticket issued so far. Anything longer cannot be
    /// genuine and is refused before the AEAD sees it, which closes
    /// off the partitioning-oracle attacks that feed an AEAD
    /// oversized forgeries (eprint 2020/1491).
    longest: AtomicUsize,
}

impl Ticketer {
    // The rotator calls this for each new key.
    #[expect(clippy::new_ret_no_self)]
    fn new() -> Result<Box<dyn TicketProducer>, Error> {
        let algorithm = Algorithm::ChaCha20Poly1305;
        let mut key = [0u8; 32];
        let mut key_name = [0u8; KEY_NAME_LEN];
        let drawn = random::fill(&mut key).and(random::fill(&mut key_name));
        let sealing = algorithm.key(&key);
        zeroize::Zeroize::zeroize(&mut key);
        drawn.map_err(|_| Error::FailedToGetRandomBytes)?;
        let key = sealing.ok_or(Error::FailedToGetRandomBytes)?;
        Ok(Box::new(Ticketer {
            key,
            key_name,
            longest: AtomicUsize::new(0),
        }))
    }
}

/// Nothing about the key.
impl fmt::Debug for Ticketer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticketer").finish_non_exhaustive()
    }
}

impl TicketProducer for Ticketer {
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        random::fill(&mut nonce).ok()?;
        let mut ticket = Vec::with_capacity(
            KEY_NAME_LEN + NONCE_LEN + plain.len() + TAG_LEN,
        );
        ticket.extend_from_slice(&self.key_name);
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(plain);
        let body = &mut ticket[KEY_NAME_LEN + NONCE_LEN..];
        let tag = self.key.seal(&nonce, &self.key_name, body).ok()?;
        ticket.extend_from_slice(&tag);
        self.longest.fetch_max(ticket.len(), Ordering::SeqCst);
        Some(ticket)
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        if ticket.len() > self.longest.load(Ordering::SeqCst) {
            return None;
        }
        let (name, rest) = ticket.split_at_checked(KEY_NAME_LEN)?;
        let (nonce, sealed) = rest.split_at_checked(NONCE_LEN)?;
        if !constant_time::equal(name, &self.key_name) {
            return None;
        }
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().ok()?;
        let mut body = sealed.to_vec();
        let len = self.key.open(nonce, &self.key_name, &mut body).ok()?;
        body.truncate(len);
        Some(body)
    }

    /// Unused: the rotator above it answers for the lifetime.
    fn lifetime(&self) -> Duration {
        Duration::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let t = Ticketer::new().unwrap();
        let ticket = t.encrypt(b"resumption state").unwrap();
        assert_eq!(ticket.len(), 16 + 12 + 16 + 16);
        assert_eq!(t.decrypt(&ticket).unwrap(), b"resumption state");
        // Two tickets for the same state differ: the nonce is fresh.
        assert_ne!(t.encrypt(b"resumption state").unwrap(), ticket);
    }

    #[test]
    fn refuses_what_it_did_not_make() {
        let t = Ticketer::new().unwrap();
        // Nothing issued yet, so nothing can be genuine.
        assert!(t.decrypt(&[0u8; 60]).is_none());
        let ticket = t.encrypt(b"state").unwrap();
        // Every byte matters: name, nonce, body and tag.
        for i in 0..ticket.len() {
            let mut bent = ticket.clone();
            bent[i] ^= 1;
            assert!(t.decrypt(&bent).is_none(), "byte {i}");
        }
        // Longer than anything issued, and every shorter length,
        // down to nothing: refused, without panicking.
        let mut long = ticket.clone();
        long.push(0);
        assert!(t.decrypt(&long).is_none());
        for n in 0..ticket.len() {
            assert!(t.decrypt(&ticket[..n]).is_none(), "length {n}");
        }
        // Another key's ticket.
        let other = Ticketer::new().unwrap();
        assert!(other.decrypt(&ticket).is_none());
    }

    #[test]
    fn factory_rotates() {
        let ticketer = Tickets.ticketer().unwrap();
        let ticket = ticketer.encrypt(b"state").unwrap();
        assert_eq!(ticketer.decrypt(&ticket).unwrap(), b"state");
        assert_eq!(ticketer.lifetime(), LIFETIME);
    }
}
