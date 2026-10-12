//! The AEADs TLS uses, behind one type, so the record layers and
//! QUIC are written once.

use scytale::aead::{Aead as _, Ccm, ChaCha20Poly1305, Gcm};
use scytale::cipher::aes::{Aes128, Aes256};
use scytale::{Error, Key};

/// The length of a full tag: every AEAD here but the CCM_8 forms.
pub(crate) const TAG_LEN: usize = 16;

/// The length of the CCM_8 forms' tag.
const SHORT_TAG_LEN: usize = 8;

/// The length of every nonce here.
pub(crate) const NONCE_LEN: usize = 12;

/// An AEAD, without a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Ccm,
    Aes256Ccm,
    /// AES-128-CCM with an 8-byte tag.
    Aes128Ccm8,
    /// AES-256-CCM with an 8-byte tag.
    Aes256Ccm8,
}

impl Algorithm {
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm
            | Algorithm::Aes128Ccm
            | Algorithm::Aes128Ccm8 => 16,
            Algorithm::Aes256Gcm
            | Algorithm::ChaCha20Poly1305
            | Algorithm::Aes256Ccm
            | Algorithm::Aes256Ccm8 => 32,
        }
    }

    pub(crate) const fn tag_len(self) -> usize {
        match self {
            Algorithm::Aes128Ccm8 | Algorithm::Aes256Ccm8 => SHORT_TAG_LEN,
            _ => TAG_LEN,
        }
    }

    /// The AEAD keyed with `bytes`, its key schedule built once.
    /// `None` for a key of the wrong length, which rustls never
    /// hands over; the caller then fails every operation rather than
    /// panicking.
    pub(crate) fn key(self, bytes: &[u8]) -> Option<SealingKey> {
        let cipher = match self {
            Algorithm::Aes128Gcm => {
                Cipher::Aes128Gcm(Gcm::new(&Key::try_from(bytes).ok()?))
            }
            Algorithm::Aes256Gcm => {
                Cipher::Aes256Gcm(Gcm::new(&Key::try_from(bytes).ok()?))
            }
            Algorithm::ChaCha20Poly1305 => Cipher::ChaCha20Poly1305(
                ChaCha20Poly1305::new(&Key::try_from(bytes).ok()?),
            ),
            Algorithm::Aes128Ccm | Algorithm::Aes128Ccm8 => {
                Cipher::Aes128Ccm(Ccm::new(&Key::try_from(bytes).ok()?))
            }
            Algorithm::Aes256Ccm | Algorithm::Aes256Ccm8 => {
                Cipher::Aes256Ccm(Ccm::new(&Key::try_from(bytes).ok()?))
            }
        };
        Some(SealingKey {
            cipher,
            tag_len: self.tag_len(),
        })
    }
}

/// A keyed AEAD, which both seals and opens, and the length of tag
/// it makes. Each cipher wipes its key schedule on drop.
pub(crate) struct SealingKey {
    cipher: Cipher,
    tag_len: usize,
}

enum Cipher {
    Aes128Gcm(Gcm<Aes128>),
    Aes256Gcm(Gcm<Aes256>),
    ChaCha20Poly1305(ChaCha20Poly1305),
    // CCM's tag length is a parameter of the mode, so one schedule
    // serves both forms.
    Aes128Ccm(Ccm<Aes128>),
    Aes256Ccm(Ccm<Aes256>),
}

/// A tag, as long as the AEAD that made it says.
pub(crate) struct Tag {
    bytes: [u8; TAG_LEN],
    len: usize,
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl SealingKey {
    /// Encrypts `data` in place and returns the tag.
    pub(crate) fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<Tag, Error> {
        let mut bytes = [0u8; TAG_LEN];
        let short = self.tag_len;
        match &self.cipher {
            Cipher::Aes128Gcm(k) => k.encrypt(nonce, aad, data, &mut bytes),
            Cipher::Aes256Gcm(k) => k.encrypt(nonce, aad, data, &mut bytes),
            Cipher::ChaCha20Poly1305(k) => {
                k.encrypt(nonce, aad, data, &mut bytes)
            }
            Cipher::Aes128Ccm(k) => {
                Ccm::encrypt(k, nonce, aad, data, &mut bytes[..short])
            }
            Cipher::Aes256Ccm(k) => {
                Ccm::encrypt(k, nonce, aad, data, &mut bytes[..short])
            }
        }?;
        Ok(Tag {
            bytes,
            len: self.tag_len,
        })
    }

    /// Checks and decrypts `data`, which ends in the tag, in place,
    /// returning the plaintext's length. Too short to hold a tag, or
    /// a tag that does not check, is an error, and the plaintext is
    /// then wiped.
    pub(crate) fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<usize, Error> {
        let len = data
            .len()
            .checked_sub(self.tag_len)
            .ok_or(Error::AuthenticationFailed)?;
        let (text, tag) = data.split_at_mut(len);
        let mut received = [0u8; TAG_LEN];
        received[..self.tag_len].copy_from_slice(tag);
        match &self.cipher {
            Cipher::Aes128Gcm(k) => k.decrypt(nonce, aad, text, &received),
            Cipher::Aes256Gcm(k) => k.decrypt(nonce, aad, text, &received),
            Cipher::ChaCha20Poly1305(k) => {
                k.decrypt(nonce, aad, text, &received)
            }
            Cipher::Aes128Ccm(k) => Ccm::decrypt(k, nonce, aad, text, tag),
            Cipher::Aes256Ccm(k) => Ccm::decrypt(k, nonce, aad, text, tag),
        }?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 section 2.8.2: the AEAD's own example, sealed and
    /// opened through the shared type.
    #[test]
    fn rfc8439_example() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
            0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6,
            0xc7,
        ];
        let plain = *b"Ladies and Gentlemen of the class of '99: If I could \
            offer you only one tip for the future, sunscreen would be it.";
        let key = Algorithm::ChaCha20Poly1305.key(&key).unwrap();
        let mut data = alloc::vec::Vec::from(&plain[..]);
        let tag = key.seal(&nonce, &aad, &mut data).unwrap();
        assert_eq!(
            tag.as_ref(),
            [
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90,
                0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
            ]
        );
        assert_eq!(data[..4], [0xd3, 0x1a, 0x8d, 0x34]);
        data.extend_from_slice(tag.as_ref());
        let n = key.open(&nonce, &aad, &mut data).unwrap();
        assert_eq!(data[..n], plain[..]);
        // A flipped bit anywhere is refused.
        data.clear();
        data.extend_from_slice(&plain);
        let tag = key.seal(&nonce, &aad, &mut data).unwrap();
        data.extend_from_slice(tag.as_ref());
        data[0] ^= 1;
        assert!(key.open(&nonce, &aad, &mut data).is_err());
    }

    #[test]
    fn wrong_key_length_and_short_input() {
        assert!(Algorithm::Aes128Gcm.key(&[0; 32]).is_none());
        assert!(Algorithm::Aes256Gcm.key(&[0; 16]).is_none());
        let key = Algorithm::Aes128Gcm.key(&[0; 16]).unwrap();
        assert!(key.open(&[0; 12], b"", &mut [0; 15]).is_err());
        assert_eq!(Algorithm::Aes256Gcm.key_len(), 32);
        // An 8-byte tag's shortest record is eight bytes.
        let key = Algorithm::Aes128Ccm8.key(&[0; 16]).unwrap();
        assert!(key.open(&[0; 12], b"", &mut [0; 7]).is_err());
    }

    /// The CCM forms seal as scytale's mode does called directly, with
    /// the tag each names, and open what they seal. CCM authenticates
    /// the tag's length, so the 8-byte tag is not the 16-byte one cut
    /// short, and neither form opens the other's records.
    #[test]
    fn ccm_tags() {
        let nonce = [5u8; NONCE_LEN];
        let plain = *b"a record of some length";
        for (full, short, key) in [
            (Algorithm::Aes128Ccm, Algorithm::Aes128Ccm8, &[1u8; 16][..]),
            (Algorithm::Aes256Ccm, Algorithm::Aes256Ccm8, &[2u8; 32][..]),
        ] {
            let (full, short) =
                (full.key(key).unwrap(), short.key(key).unwrap());
            let mut a = plain;
            let long_tag = full.seal(&nonce, b"aad", &mut a).unwrap();
            let mut b = plain;
            let short_tag = short.seal(&nonce, b"aad", &mut b).unwrap();
            assert_eq!(long_tag.as_ref().len(), 16);
            assert_eq!(short_tag.as_ref().len(), 8);
            assert_eq!(a, b);
            assert_ne!(short_tag.as_ref(), &long_tag.as_ref()[..8]);

            let mut direct = plain;
            let mut want = [0u8; 8];
            match key.len() {
                16 => Ccm::<Aes128>::new(&Key::try_from(key).unwrap()).encrypt(
                    &nonce,
                    b"aad",
                    &mut direct,
                    &mut want,
                ),
                _ => Ccm::<Aes256>::new(&Key::try_from(key).unwrap()).encrypt(
                    &nonce,
                    b"aad",
                    &mut direct,
                    &mut want,
                ),
            }
            .unwrap();
            assert_eq!(direct, b);
            assert_eq!(short_tag.as_ref(), want);

            let mut record = alloc::vec::Vec::from(&b[..]);
            record.extend_from_slice(short_tag.as_ref());
            let mut copy = record.clone();
            let n = short.open(&nonce, b"aad", &mut copy).unwrap();
            assert_eq!(copy[..n], plain);
            assert!(full.open(&nonce, b"aad", &mut record).is_err());
        }
    }
}
