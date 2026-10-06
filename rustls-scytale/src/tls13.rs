//! The TLS 1.3 cipher suites and their record protection
//! (RFC 8446 section 5.2).

use alloc::boxed::Box;

use rustls::ConnectionTrafficSecrets;
use rustls::Error;
use rustls::Tls13CipherSuite;
use rustls::crypto::CipherSuite;
use rustls::crypto::CipherSuiteCommon;
use rustls::crypto::cipher::{
    AeadKey, EncodedMessage, EncryptBuffer, InboundOpaque, Iv,
    MessageDecrypter, MessageEncrypter, Nonce, OutboundPlain,
    Tls13AeadAlgorithm, UnsupportedOperationError, make_tls13_aad,
};
use rustls::enums::{ContentType, ProtocolVersion};
use rustls::version::TLS13_VERSION;

use crate::aead::{Algorithm, SealingKey, TAG_LEN};
use crate::{hash, hkdf, quic};

/// TLS13_AES_128_GCM_SHA256.
pub static TLS13_AES_128_GCM_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &hash::SHA256,
        // RFC 8446 section 5.5, for AES-GCM.
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &hkdf::HKDF_SHA256,
    aead_alg: &Aead(Algorithm::Aes128Gcm),
    quic: Some(&quic::AES_128_GCM),
};

/// TLS13_AES_256_GCM_SHA384.
pub static TLS13_AES_256_GCM_SHA384: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &hkdf::HKDF_SHA384,
    aead_alg: &Aead(Algorithm::Aes256Gcm),
    quic: Some(&quic::AES_256_GCM),
};

/// TLS13_CHACHA20_POLY1305_SHA256.
pub static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite =
    &Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            // No limit of its own short of the sequence numbers.
            confidentiality_limit: u64::MAX,
        },
        protocol_version: TLS13_VERSION,
        hkdf_provider: &hkdf::HKDF_SHA256,
        aead_alg: &Aead(Algorithm::ChaCha20Poly1305),
        quic: Some(&quic::CHACHA20_POLY1305),
    };

struct Aead(Algorithm);

impl Tls13AeadAlgorithm for Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Protection {
            key: self.0.key(key.as_ref()),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Protection {
            key: self.0.key(key.as_ref()),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self.0 {
            Algorithm::Aes128Gcm => {
                ConnectionTrafficSecrets::Aes128Gcm { key, iv }
            }
            Algorithm::Aes256Gcm => {
                ConnectionTrafficSecrets::Aes256Gcm { key, iv }
            }
            Algorithm::ChaCha20Poly1305 => {
                ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
            }
        })
    }
}

/// One direction's record protection: the keyed AEAD and the IV
/// each record's nonce is the sequence number XORed into.
struct Protection {
    key: Option<SealingKey>,
    iv: Iv,
}

impl MessageEncrypter for Protection {
    fn encrypt<'a>(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let key = self.key.as_ref().ok_or(Error::EncryptError)?;
        // TLSInnerPlaintext: the content, then its real type, with no
        // padding; then the tag.
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut buf = EncryptBuffer::new(out, total)?;
        buf.extend_from_chunks(&msg.payload);
        buf.extend_from_slice(&msg.typ.to_array());
        let nonce = Nonce::new(&self.iv, seq).to_array()?;
        let tag = key
            .seal(&nonce, &make_tls13_aad(total), buf.as_mut())
            .map_err(|_| Error::EncryptError)?;
        buf.extend_from_slice(&tag);
        // Every protected record claims to be TLS 1.2 application
        // data (RFC 8446 section 5.1).
        Ok(EncodedMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            buf.into_written(),
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Protection {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        // Exactly `DecryptError` for every failure of the AEAD: that
        // is what rustls looks for when it trial-decrypts rejected
        // early data.
        let key = self.key.as_ref().ok_or(Error::DecryptError)?;
        let payload = &mut msg.payload;
        let nonce = Nonce::new(&self.iv, seq).to_array()?;
        let aad = make_tls13_aad(payload.len());
        let len = key
            .open(&nonce, &aad, payload)
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(len);
        // Strips the padding, reads the real type, and checks the
        // record's size.
        msg.into_tls13_unpadded_message()
    }
}
