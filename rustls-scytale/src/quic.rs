//! QUIC packet and header protection (RFC 9001 section 5).

use alloc::boxed::Box;

use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::error::ApiMisuse;
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};
use scytale::Key;
use scytale::cipher::aes::{Aes128, Aes256};
use scytale::cipher::chacha20::ChaCha20;

use crate::aead::{self, SealingKey};

pub(crate) static AES_128_GCM: Quic = Quic(aead::Algorithm::Aes128Gcm);
pub(crate) static AES_256_GCM: Quic = Quic(aead::Algorithm::Aes256Gcm);
pub(crate) static CHACHA20_POLY1305: Quic =
    Quic(aead::Algorithm::ChaCha20Poly1305);
// AES-128-CCM's 8-byte-tag form has none: RFC 9001 section 5.3
// forbids it in QUIC.
pub(crate) static AES_128_CCM: Quic = Quic(aead::Algorithm::Aes128Ccm);

/// RFC 9001 section 6.6's limit for AES-128-CCM, both of them:
/// 2^21.5, rounded down.
const CCM_LIMIT: u64 = 2_965_820;

/// The sample header protection takes from the packet, for every
/// cipher here.
const SAMPLE_LEN: usize = 16;

/// The mask: one byte for the first byte's low bits, four for the
/// longest packet number.
const MASK_LEN: usize = 5;

/// One of TLS 1.3's AEADs, as QUIC uses it.
pub(crate) struct Quic(aead::Algorithm);

impl Algorithm for Quic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(Packets {
            key: self.0.key(key.as_ref()),
            iv,
            algorithm: self.0,
        })
    }

    fn header_protection_key(
        &self,
        key: AeadKey,
    ) -> Box<dyn HeaderProtectionKey> {
        let key = key.as_ref();
        // Every AES AEAD masks with the block cipher alone (RFC 9001
        // section 5.4.3).
        let mask = match self.0 {
            aead::Algorithm::Aes128Gcm
            | aead::Algorithm::Aes128Ccm
            | aead::Algorithm::Aes128Ccm8 => Key::try_from(key)
                .ok()
                .map(|k| Masker::Aes128(Aes128::new(&k))),
            aead::Algorithm::Aes256Gcm
            | aead::Algorithm::Aes256Ccm
            | aead::Algorithm::Aes256Ccm8 => Key::try_from(key)
                .ok()
                .map(|k| Masker::Aes256(Aes256::new(&k))),
            aead::Algorithm::ChaCha20Poly1305 => Key::try_from(key)
                .ok()
                .map(|k| Masker::ChaCha20(ChaCha20::new(&k))),
        };
        Box::new(Headers(mask))
    }

    fn aead_key_len(&self) -> usize {
        self.0.key_len()
    }
}

/// Packet protection: the AEAD under the packet's nonce, with the
/// header as associated data.
struct Packets {
    key: Option<SealingKey>,
    iv: Iv,
    algorithm: aead::Algorithm,
}

impl PacketKey for Packets {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
        path_id: Option<u32>,
    ) -> Result<Tag, Error> {
        let key = self.key.as_ref().ok_or(Error::EncryptError)?;
        let nonce = Nonce::quic(path_id, &self.iv, packet_number).to_array()?;
        let tag = key
            .seal(&nonce, header, payload)
            .map_err(|_| Error::EncryptError)?;
        Ok(Tag::from(tag.as_ref()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
        path_id: Option<u32>,
    ) -> Result<&'a [u8], Error> {
        let key = self.key.as_ref().ok_or(Error::DecryptError)?;
        let nonce = Nonce::quic(path_id, &self.iv, packet_number).to_array()?;
        let len = key
            .open(&nonce, header, payload)
            .map_err(|_| Error::DecryptError)?;
        Ok(&payload[..len])
    }

    fn tag_len(&self) -> usize {
        self.algorithm.tag_len()
    }

    /// RFC 9001 section 6.6.
    fn confidentiality_limit(&self) -> u64 {
        match self.algorithm {
            aead::Algorithm::ChaCha20Poly1305 => u64::MAX,
            aead::Algorithm::Aes128Ccm => CCM_LIMIT,
            _ => 1 << 23,
        }
    }

    /// RFC 9001 section 6.6.
    fn integrity_limit(&self) -> u64 {
        match self.algorithm {
            aead::Algorithm::ChaCha20Poly1305 => 1 << 36,
            aead::Algorithm::Aes128Ccm => CCM_LIMIT,
            _ => 1 << 52,
        }
    }
}

/// The cipher a header protection mask comes from.
enum Masker {
    Aes128(Aes128),
    Aes256(Aes256),
    ChaCha20(ChaCha20),
}

impl Masker {
    /// RFC 9001 section 5.4.3 for AES: the sample is one block,
    /// encrypted. Section 5.4.4 for ChaCha20: the sample's first four
    /// bytes are the block counter and the rest the nonce, and the
    /// mask is the keystream.
    fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> Option<[u8; MASK_LEN]> {
        let mut mask = [0u8; MASK_LEN];
        match self {
            Masker::Aes128(aes) => {
                let mut block = *sample;
                aes.encrypt(core::slice::from_mut(&mut block));
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            Masker::Aes256(aes) => {
                let mut block = *sample;
                aes.encrypt(core::slice::from_mut(&mut block));
                mask.copy_from_slice(&block[..MASK_LEN]);
            }
            Masker::ChaCha20(chacha) => {
                let (counter, nonce) = sample.split_at(4);
                let counter = u32::from_le_bytes(counter.try_into().ok()?);
                chacha
                    .encrypt(nonce.try_into().ok()?, counter, &mut mask)
                    .ok()?;
            }
        }
        Some(mask)
    }
}

/// Header protection.
struct Headers(Option<Masker>);

impl Headers {
    /// Applies the mask (RFC 9001 section 5.4.1). The packet number's
    /// length is in the first byte's low bits, which are protected
    /// too: read before masking when protecting, after unmasking when
    /// removing it. Nothing is changed unless everything checks.
    fn xor(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        unmasking: bool,
    ) -> Result<(), Error> {
        let sample: &[u8; SAMPLE_LEN] = sample.try_into().map_err(|_| {
            Error::from(ApiMisuse::InvalidQuicHeaderProtectionSampleLength)
        })?;
        if packet_number.len() > MASK_LEN - 1 {
            return Err(
                ApiMisuse::InvalidQuicHeaderProtectionPacketNumberLength.into(),
            );
        }
        let masker = self.0.as_ref().ok_or(Error::EncryptError)?;
        let mask = masker.mask(sample).ok_or(Error::EncryptError)?;
        // A long header (top bit set) protects four bits of the first
        // byte, a short one five.
        let bits = if *first & 0x80 != 0 { 0x0f } else { 0x1f };
        let plain_first = if unmasking {
            *first ^ (mask[0] & bits)
        } else {
            *first
        };
        let pn_len = usize::from(plain_first & 0x03) + 1;
        *first ^= mask[0] & bits;
        for (byte, m) in packet_number.iter_mut().zip(&mask[1..]).take(pn_len) {
            *byte ^= m;
        }
        Ok(())
    }
}

impl HeaderProtectionKey for Headers {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn aead_key(bytes: &[u8]) -> AeadKey {
        let mut buf = [0u8; 32];
        buf[..bytes.len()].copy_from_slice(bytes);
        match bytes.len() {
            16 => AeadKey::from(<[u8; 16]>::try_from(bytes).unwrap()),
            _ => AeadKey::from(buf),
        }
    }

    /// RFC 9001 appendix A.5: a short-header packet under
    /// ChaCha20-Poly1305, protected and unprotected.
    #[test]
    fn rfc9001_chacha20_short_header() {
        let key = aead_key(&unhex(
            "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
        ));
        let iv = Iv::new(&unhex("e0459b3474bdd0e44a41c144")).unwrap();
        let hp = aead_key(&unhex(
            "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
        ));
        let packets = CHACHA20_POLY1305.packet_key(key, iv);
        let headers = CHACHA20_POLY1305.header_protection_key(hp);

        let header = unhex("4200bff4");
        let mut payload = unhex("01");
        let tag = packets
            .encrypt_in_place(654_360_564, &header, &mut payload, None)
            .unwrap();
        payload.extend_from_slice(tag.as_ref());
        assert_eq!(payload, unhex("655e5cd55c41f69080575d7999c25a5bfb"));

        let sample = &payload[1..17];
        let mut first = header[0];
        let mut pn = header[1..].to_vec();
        headers
            .encrypt_in_place(sample, &mut first, &mut pn)
            .unwrap();
        assert_eq!([first, pn[0], pn[1], pn[2]], [0x4c, 0xfe, 0x41, 0x89]);
        headers
            .decrypt_in_place(sample, &mut first, &mut pn)
            .unwrap();
        assert_eq!([first, pn[0], pn[1], pn[2]], [0x42, 0x00, 0xbf, 0xf4]);

        let plain = packets
            .decrypt_in_place(654_360_564, &header, &mut payload, None)
            .unwrap();
        assert_eq!(plain, [0x01]);
    }

    /// RFC 9001 appendices A.2 and A.3: the AES-128 header protection
    /// masks of the client's and the server's Initial packets.
    #[test]
    fn rfc9001_aes_masks() {
        for (hp, sample, mask) in [
            (
                "9f50449e04a0e810283a1e9933adedd2",
                "d1b1c98dd7689fb8ec11d242b123dc9b",
                "437b9aec36",
            ),
            (
                "c206b8d9b9f0f37644430b490eeaa314",
                "2cd0991cd25b0aac406a5816b6394100",
                "2ec0d8356a",
            ),
        ] {
            let headers =
                AES_128_GCM.header_protection_key(aead_key(&unhex(hp)));
            let mask = unhex(mask);
            // A long header with a four-byte packet number: four bits
            // of the first byte and all four number bytes masked.
            let mut first = 0xc3;
            let mut pn = [0u8; 4];
            headers
                .encrypt_in_place(&unhex(sample), &mut first, &mut pn)
                .unwrap();
            assert_eq!(first, 0xc3 ^ (mask[0] & 0x0f));
            assert_eq!(pn[..], mask[1..]);
        }
    }

    #[test]
    fn bad_lengths_change_nothing() {
        let headers = AES_256_GCM.header_protection_key(aead_key(&[7; 32]));
        let mut first = 0x40;
        let mut pn = [1u8, 2];
        assert!(
            headers
                .encrypt_in_place(&[0; 15], &mut first, &mut pn)
                .is_err()
        );
        let mut long = [0u8; 5];
        assert!(
            headers
                .encrypt_in_place(&[0; 16], &mut first, &mut long)
                .is_err()
        );
        assert_eq!((first, pn), (0x40, [1, 2]));
        assert_eq!(headers.sample_len(), 16);
    }

    /// A packet round-trips under each AEAD, on a path as multipath
    /// QUIC numbers them, and the wrong path or number fails.
    #[test]
    fn packets_round_trip() {
        for quic in
            [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305, &AES_128_CCM]
        {
            let key = aead_key(&[3; 32][..quic.aead_key_len()]);
            let iv = Iv::new(&[9; 12]).unwrap();
            let packets = quic.packet_key(key, iv);
            let mut payload = b"payload".to_vec();
            let tag = packets
                .encrypt_in_place(5, b"hdr", &mut payload, Some(2))
                .unwrap();
            payload.extend_from_slice(tag.as_ref());
            let mut copy = payload.clone();
            assert!(
                packets
                    .decrypt_in_place(5, b"hdr", &mut copy, None)
                    .is_err()
            );
            let mut copy = payload.clone();
            assert!(
                packets
                    .decrypt_in_place(6, b"hdr", &mut copy, Some(2))
                    .is_err()
            );
            let plain = packets
                .decrypt_in_place(5, b"hdr", &mut payload, Some(2))
                .unwrap();
            assert_eq!(plain, b"payload");
        }
    }
}
