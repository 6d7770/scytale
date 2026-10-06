//! HKDF, under the TLS 1.3 key schedule.

use alloc::boxed::Box;
use core::marker::PhantomData;

use rustls::crypto::hmac::Tag;
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use scytale::BlockType;
use scytale::hash::sha2::{Sha256, Sha384};
use scytale::kdf::hkdf;
use scytale::mac::hmac::Hmac;
use zeroize::Zeroize;

/// HKDF over one of scytale's hashes.
pub(crate) struct HkdfOver<H>(PhantomData<fn() -> H>);

pub(crate) static HKDF_SHA256: HkdfOver<Sha256> = HkdfOver(PhantomData);
pub(crate) static HKDF_SHA384: HkdfOver<Sha384> = HkdfOver(PhantomData);

/// The longest digest here, SHA-512's; rustls's blocks are the same.
const MAX_DIGEST: usize = OkmBlock::MAX_LEN;

impl<H> HkdfOver<H>
where
    H: scytale::hash::Hash
        + Clone
        + BlockType
        + Default
        + Send
        + Sync
        + 'static,
{
    fn extract(
        &self,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> Box<dyn HkdfExpander> {
        // No salt is a digest's worth of zeros (RFC 5869 section 2.2).
        let zeros = [0u8; MAX_DIGEST];
        let salt = salt.unwrap_or(&zeros[..size_of::<H::Output>()]);
        let mut prk = hkdf::extract::<H>(salt, ikm);
        let expander = Expander::<H>::new(prk.as_ref());
        prk.as_mut().zeroize();
        Box::new(expander)
    }
}

impl<H> Hkdf for HkdfOver<H>
where
    H: scytale::hash::Hash
        + Clone
        + BlockType
        + Default
        + Send
        + Sync
        + 'static,
{
    fn extract_from_zero_ikm(
        &self,
        salt: Option<&[u8]>,
    ) -> Box<dyn HkdfExpander> {
        let zeros = [0u8; MAX_DIGEST];
        self.extract(salt, &zeros[..size_of::<H::Output>()])
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn HkdfExpander> {
        self.extract(salt, secret)
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(Expander::<H>::new(okm.as_ref()))
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        Tag::new(Hmac::<H>::mac(key.as_ref(), message).as_ref())
    }
}

/// A pseudorandom key, ready to expand; wiped on drop.
struct Expander<H> {
    prk: [u8; MAX_DIGEST],
    len: usize,
    hash: PhantomData<fn() -> H>,
}

impl<H> Expander<H> {
    fn new(prk: &[u8]) -> Self {
        let mut buf = [0u8; MAX_DIGEST];
        let len = prk.len().min(MAX_DIGEST);
        buf[..len].copy_from_slice(&prk[..len]);
        Expander {
            prk: buf,
            len,
            hash: PhantomData,
        }
    }
}

impl<H> Drop for Expander<H> {
    fn drop(&mut self) {
        self.prk.zeroize();
    }
}

impl<H> HkdfExpander for Expander<H>
where
    H: scytale::hash::Hash
        + Clone
        + BlockType
        + Default
        + Send
        + Sync
        + 'static,
{
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), OutputLengthError> {
        hkdf::expand::<H>(&self.prk[..self.len], info, output)
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut out = [0u8; MAX_DIGEST];
        let block = &mut out[..size_of::<H::Output>()];
        // One digest is always within HKDF's limit of 255, which is
        // the only thing `expand` refuses.
        let expanded = hkdf::expand::<H>(&self.prk[..self.len], info, block);
        debug_assert!(expanded.is_ok());
        let okm = OkmBlock::new(block);
        out.zeroize();
        okm
    }

    fn hash_len(&self) -> usize {
        size_of::<H::Output>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 test case 1, through extract and expand.
    #[test]
    fn rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let expander = HKDF_SHA256.extract_from_secret(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        expander
            .expand_slice(&[&info[..5], &info[5..]], &mut okm)
            .unwrap();
        assert_eq!(
            okm[..],
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c\
                 5db02d56ecc4c5bf34007208d5b887185865"
            )[..]
        );
        assert_eq!(expander.hash_len(), 32);
    }

    /// RFC 5869 test case 3: no salt and no info, which is a
    /// digest's worth of zeros and nothing.
    #[test]
    fn rfc5869_case_3() {
        let ikm = [0x0b; 22];
        let expander = HKDF_SHA256.extract_from_secret(None, &ikm);
        let mut okm = [0u8; 42];
        expander.expand_slice(&[], &mut okm).unwrap();
        assert_eq!(
            okm[..],
            unhex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879e\
                 c3454e5f3c738d2d9d201395faa4b61a96c8"
            )[..]
        );
        // A block is the first digest of the same expansion.
        assert_eq!(expander.expand_block(&[]).as_ref(), &okm[..32]);
    }

    /// More than 255 digests is refused rather than truncated.
    #[test]
    fn output_length_bound() {
        let expander = HKDF_SHA256.extract_from_zero_ikm(None);
        let mut ok = alloc::vec![0u8; 255 * 32];
        assert!(expander.expand_slice(&[], &mut ok).is_ok());
        let mut too_long = alloc::vec![0u8; 255 * 32 + 1];
        assert!(expander.expand_slice(&[], &mut too_long).is_err());
    }

    /// The Finished MAC is HMAC under the block, and an expander made
    /// from a block expands as one made from the same PRK.
    #[test]
    fn hmac_sign_and_okm_expander() {
        let block = OkmBlock::new(&[7u8; 48]);
        let tag = HKDF_SHA384.hmac_sign(&block, b"transcript");
        assert_eq!(
            tag.as_ref(),
            Hmac::<Sha384>::mac(&[7u8; 48], b"transcript")
        );
        let a = HKDF_SHA384.expander_for_okm(&block).expand_block(&[b"x"]);
        let mut b = [0u8; 48];
        hkdf::expand::<Sha384>(&[7u8; 48], &[b"x"], &mut b).unwrap();
        assert_eq!(a.as_ref(), b);
    }
}
