//! The TLS 1.2 PRF, from `scytale::kdf::tls12`.

use alloc::boxed::Box;
use core::marker::PhantomData;

use rustls::Error;
use rustls::crypto::kx::ActiveKeyExchange;
use rustls::crypto::tls12::{Prf, PrfSecret};
use rustls::enums::ProtocolVersion;
use scytale::BlockType;
use scytale::hash::sha2::{Sha256, Sha384};
use scytale::kdf::tls12;
use zeroize::Zeroizing;

/// The PRF over one of scytale's hashes: the cipher suite's.
pub(crate) struct PrfOver<H>(PhantomData<fn() -> H>);

pub(crate) static PRF_SHA256: PrfOver<Sha256> = PrfOver(PhantomData);
pub(crate) static PRF_SHA384: PrfOver<Sha384> = PrfOver(PhantomData);

impl<H> Prf for PrfOver<H>
where
    H: scytale::hash::Hash
        + Clone
        + BlockType
        + Default
        + Send
        + Sync
        + 'static,
{
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        let secret = kx
            .complete_for_tls_version(peer_pub_key, ProtocolVersion::TLSv1_2)?;
        tls12::prf::<H>(secret.secret_bytes(), label, &[seed], output);
        Ok(())
    }

    fn new_secret(&self, master_secret: &[u8; 48]) -> Box<dyn PrfSecret> {
        Box::new(Master::<H> {
            secret: Zeroizing::new(*master_secret),
            hash: PhantomData,
        })
    }
}

/// A master secret, kept for the key block, the Finished messages
/// and any exporter; wiped on drop.
struct Master<H> {
    secret: Zeroizing<[u8; 48]>,
    hash: PhantomData<fn() -> H>,
}

impl<H> PrfSecret for Master<H>
where
    H: scytale::hash::Hash
        + Clone
        + BlockType
        + Default
        + Send
        + Sync
        + 'static,
{
    /// rustls documents a label as always present, but its exporter
    /// passes the application's through, which may be empty; the PRF
    /// takes either.
    fn prf(&self, output: &mut [u8], label: &[u8], seed: &[u8]) {
        tls12::prf::<H>(&*self.secret, label, &[seed], output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key block from a master secret matches the library's PRF
    /// called directly, and differs by hash.
    #[test]
    fn master_secret_derives() {
        let master = [9u8; 48];
        let mut a = [0u8; 104];
        PRF_SHA256
            .new_secret(&master)
            .prf(&mut a, b"key expansion", b"seed");
        let mut b = [0u8; 104];
        tls12::prf::<Sha256>(&master, b"key expansion", &[b"seed"], &mut b);
        assert_eq!(a, b);
        let mut c = [0u8; 104];
        PRF_SHA384
            .new_secret(&master)
            .prf(&mut c, b"key expansion", b"seed");
        assert_ne!(a, c);
        // Nothing asked, nothing done; an empty label, as an exporter
        // may pass, is the seed alone.
        PRF_SHA256.new_secret(&master).prf(&mut [], b"l", b"s");
        let mut empty = [0u8; 32];
        PRF_SHA256.new_secret(&master).prf(&mut empty, b"", b"ab");
        let mut moved = [0u8; 32];
        PRF_SHA256.new_secret(&master).prf(&mut moved, b"a", b"b");
        assert_eq!(empty, moved);
    }
}
