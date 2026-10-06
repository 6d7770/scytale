//! The transcript hash.

use alloc::boxed::Box;
use core::marker::PhantomData;

use rustls::crypto::HashAlgorithm;
use rustls::crypto::hash::{Context, Hash, Output};
use scytale::hash::sha2::{Sha256, Sha384};

/// A hash rustls can run a transcript through.
pub(crate) struct Sha<H> {
    algorithm: HashAlgorithm,
    hash: PhantomData<fn() -> H>,
}

pub(crate) static SHA256: Sha<Sha256> = Sha {
    algorithm: HashAlgorithm::SHA256,
    hash: PhantomData,
};

pub(crate) static SHA384: Sha<Sha384> = Sha {
    algorithm: HashAlgorithm::SHA384,
    hash: PhantomData,
};

impl<H> Hash for Sha<H>
where
    H: scytale::hash::Hash + Clone + Default + Send + Sync + 'static,
{
    fn start(&self) -> Box<dyn Context> {
        Box::new(Running(H::default()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(H::digest(data).as_ref())
    }

    fn output_len(&self) -> usize {
        size_of::<H::Output>()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

/// A hash part way through. scytale's `finalize` resets the state,
/// so a digest of the prefix so far is taken from a copy.
#[derive(Clone)]
struct Running<H>(H);

impl<H> Context for Running<H>
where
    H: scytale::hash::Hash + Clone + Send + Sync + 'static,
{
    fn fork_finish(&self) -> Output {
        Output::new(self.0.clone().finalize().as_ref())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }

    fn finish(mut self: Box<Self>) -> Output {
        Output::new(self.0.finalize().as_ref())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-2's "abc", through every way of getting a digest.
    #[test]
    fn abc_every_way() {
        let want = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
            0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
            0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(SHA256.hash(b"abc").as_ref(), want);
        let mut context = SHA256.start();
        context.update(b"a");
        let fork = context.fork();
        context.update(b"bc");
        assert_eq!(context.fork_finish().as_ref(), want);
        // The fork kept only the prefix; the original goes on.
        let mut fork = fork;
        fork.update(b"bc");
        assert_eq!(fork.finish().as_ref(), want);
        assert_eq!(context.finish().as_ref(), want);
        assert_eq!(SHA256.output_len(), 32);
        assert_eq!(SHA384.output_len(), 48);
        assert_eq!(SHA384.algorithm(), HashAlgorithm::SHA384);
    }
}
