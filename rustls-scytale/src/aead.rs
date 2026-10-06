//! The three AEADs TLS uses, behind one type, so the record layers
//! and QUIC are written once.

use scytale::aead::{Aead as _, ChaCha20Poly1305, Gcm};
use scytale::cipher::aes::{Aes128, Aes256};
use scytale::{Error, Key};

/// The length of every tag here.
pub(crate) const TAG_LEN: usize = 16;

/// The length of every nonce here.
pub(crate) const NONCE_LEN: usize = 12;

/// An AEAD, without a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes256Gcm | Algorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// The AEAD keyed with `bytes`, its key schedule built once.
    /// `None` for a key of the wrong length, which rustls never
    /// hands over; the caller then fails every operation rather than
    /// panicking.
    pub(crate) fn key(self, bytes: &[u8]) -> Option<SealingKey> {
        let key = match self {
            Algorithm::Aes128Gcm => {
                SealingKey::Aes128Gcm(Gcm::new(&Key::try_from(bytes).ok()?))
            }
            Algorithm::Aes256Gcm => {
                SealingKey::Aes256Gcm(Gcm::new(&Key::try_from(bytes).ok()?))
            }
            Algorithm::ChaCha20Poly1305 => SealingKey::ChaCha20Poly1305(
                ChaCha20Poly1305::new(&Key::try_from(bytes).ok()?),
            ),
        };
        Some(key)
    }
}

/// A keyed AEAD, which both seals and opens. Each variant wipes its
/// key schedule on drop.
pub(crate) enum SealingKey {
    Aes128Gcm(Gcm<Aes128>),
    Aes256Gcm(Gcm<Aes256>),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl SealingKey {
    /// Encrypts `data` in place and returns the tag.
    pub(crate) fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        let mut tag = [0u8; TAG_LEN];
        match self {
            SealingKey::Aes128Gcm(k) => k.encrypt(nonce, aad, data, &mut tag),
            SealingKey::Aes256Gcm(k) => k.encrypt(nonce, aad, data, &mut tag),
            SealingKey::ChaCha20Poly1305(k) => {
                k.encrypt(nonce, aad, data, &mut tag)
            }
        }?;
        Ok(tag)
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
            .checked_sub(TAG_LEN)
            .ok_or(Error::AuthenticationFailed)?;
        let (text, tag) = data.split_at_mut(len);
        let mut received = [0u8; TAG_LEN];
        received.copy_from_slice(tag);
        match self {
            SealingKey::Aes128Gcm(k) => k.decrypt(nonce, aad, text, &received),
            SealingKey::Aes256Gcm(k) => k.decrypt(nonce, aad, text, &received),
            SealingKey::ChaCha20Poly1305(k) => {
                k.decrypt(nonce, aad, text, &received)
            }
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
            tag,
            [
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90,
                0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
            ]
        );
        assert_eq!(data[..4], [0xd3, 0x1a, 0x8d, 0x34]);
        data.extend_from_slice(&tag);
        let n = key.open(&nonce, &aad, &mut data).unwrap();
        assert_eq!(data[..n], plain[..]);
        // A flipped bit anywhere is refused.
        data.clear();
        data.extend_from_slice(&plain);
        let tag = key.seal(&nonce, &aad, &mut data).unwrap();
        data.extend_from_slice(&tag);
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
    }
}
