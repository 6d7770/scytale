//! The TLS 1.2 cipher suites and their record protection
//! (RFC 5288 for AES-GCM, RFC 7905 for ChaCha20-Poly1305).

use alloc::boxed::Box;

use rustls::ConnectionTrafficSecrets;
use rustls::Error;
use rustls::Tls12CipherSuite;
use rustls::crypto::cipher::{
    AeadKey, EncodedMessage, EncryptBuffer, InboundOpaque, Iv, KeyBlockShape,
    MessageDecrypter, MessageEncrypter, Nonce, OutboundPlain,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::crypto::kx::KeyExchangeAlgorithm;
use rustls::crypto::{CipherSuite, CipherSuiteCommon, SignatureScheme};
use rustls::version::TLS12_VERSION;

use crate::aead::{Algorithm, NONCE_LEN, SealingKey, TAG_LEN};
use crate::{hash, prf};

/// The most plaintext a record may carry (RFC 5246 section 6.2.1).
/// rustls checks this for TLS 1.3 itself; for 1.2 it is the
/// decrypter's to check.
const MAX_FRAGMENT_LEN: usize = 16384;

/// The schemes an ECDHE_ECDSA suite can sign the key exchange with.
/// The suite's name says ECDSA, but TLS 1.2 reads it as any key of
/// that family's algorithm byte, and Ed25519 is one (RFC 8422).
static ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// The schemes an ECDHE_RSA suite can sign the key exchange with,
/// PSS first.
static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

macro_rules! suite {
    ($(#[$doc:meta])* $name:ident, $hash:ident, $prf:ident, $sign:ident,
     $aead:ident, $limit:expr) => {
        $(#[$doc])*
        pub static $name: &Tls12CipherSuite = &Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::$name,
                hash_provider: &hash::$hash,
                confidentiality_limit: $limit,
            },
            protocol_version: TLS12_VERSION,
            prf_provider: &prf::$prf,
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $sign,
            aead_alg: &$aead,
        };
    };
}

suite!(
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    SHA256, PRF_SHA256, ECDSA_SCHEMES, AES_128_GCM, 1 << 24
);
suite!(
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    SHA384, PRF_SHA384, ECDSA_SCHEMES, AES_256_GCM, 1 << 24
);
suite!(
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256, PRF_SHA256, ECDSA_SCHEMES, CHACHA20_POLY1305, u64::MAX
);
suite!(
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SHA256, PRF_SHA256, RSA_SCHEMES, AES_128_GCM, 1 << 24
);
suite!(
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SHA384, PRF_SHA384, RSA_SCHEMES, AES_256_GCM, 1 << 24
);
suite!(
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256, PRF_SHA256, RSA_SCHEMES, CHACHA20_POLY1305, u64::MAX
);

static AES_128_GCM: GcmAead = GcmAead(Algorithm::Aes128Gcm);
static AES_256_GCM: GcmAead = GcmAead(Algorithm::Aes256Gcm);
static CHACHA20_POLY1305: ChaChaAead = ChaChaAead;

/// The salt from the key block, and the explicit part of the nonce
/// that travels with each record.
const GCM_SALT_LEN: usize = 4;
const GCM_EXPLICIT_LEN: usize = 8;

/// AES-GCM. RFC 5288 leaves the explicit nonce's construction to the
/// sender; this one starts from eight more bytes of key block and
/// XORs the sequence number in, as TLS 1.3 does, so it never
/// repeats under one key and says nothing a counter would not.
struct GcmAead(Algorithm);

impl GcmAead {
    /// The salt and the starting explicit part, as one 12-byte IV;
    /// `None` if rustls handed over parts of other lengths.
    fn iv(salt: &[u8], explicit: &[u8]) -> Option<Iv> {
        if salt.len() != GCM_SALT_LEN || explicit.len() != GCM_EXPLICIT_LEN {
            return None;
        }
        let mut iv = [0u8; NONCE_LEN];
        iv[..GCM_SALT_LEN].copy_from_slice(salt);
        iv[GCM_SALT_LEN..].copy_from_slice(explicit);
        Some(Iv::from(iv))
    }
}

impl Tls12AeadAlgorithm for GcmAead {
    fn encrypter(
        &self,
        key: AeadKey,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        let iv = Self::iv(iv, extra);
        Box::new(GcmEncrypter {
            key: iv.as_ref().and(self.0.key(key.as_ref())),
            iv: iv.unwrap_or_default(),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let salt: Option<[u8; GCM_SALT_LEN]> = iv.try_into().ok();
        Box::new(GcmDecrypter {
            key: salt.and(self.0.key(key.as_ref())),
            salt: salt.unwrap_or_default(),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0.key_len(),
            fixed_iv_len: GCM_SALT_LEN,
            explicit_nonce_len: GCM_EXPLICIT_LEN,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = Self::iv(iv, explicit).ok_or(UnsupportedOperationError)?;
        match self.0 {
            Algorithm::Aes128Gcm => {
                Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
            }
            Algorithm::Aes256Gcm => {
                Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
            }
            Algorithm::ChaCha20Poly1305 => Err(UnsupportedOperationError),
        }
    }
}

struct GcmEncrypter {
    key: Option<SealingKey>,
    iv: Iv,
}

impl MessageEncrypter for GcmEncrypter {
    fn encrypt<'a>(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let key = self.key.as_ref().ok_or(Error::EncryptError)?;
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut buf = EncryptBuffer::new(out, total)?;
        let nonce: [u8; NONCE_LEN] = Nonce::new(&self.iv, seq).to_array()?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        // The explicit part of the nonce, then the ciphertext, then
        // the tag.
        buf.extend_from_slice(&nonce[GCM_SALT_LEN..]);
        buf.extend_from_chunks(&msg.payload);
        let tag = key
            .seal(&nonce, &aad, &mut buf.as_mut()[GCM_EXPLICIT_LEN..])
            .map_err(|_| Error::EncryptError)?;
        buf.extend_from_slice(&tag);
        Ok(EncodedMessage::new(
            msg.typ,
            msg.version,
            buf.into_written(),
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        GCM_EXPLICIT_LEN + payload_len + TAG_LEN
    }
}

struct GcmDecrypter {
    key: Option<SealingKey>,
    salt: [u8; GCM_SALT_LEN],
}

impl MessageDecrypter for GcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let key = self.key.as_ref().ok_or(Error::DecryptError)?;
        let payload = &mut msg.payload;
        // The nonce is the salt and whatever the sender put on the
        // wire; a record too short to hold it and a tag is refused
        // as one that does not authenticate.
        let Some(text_len) =
            payload.len().checked_sub(GCM_EXPLICIT_LEN + TAG_LEN)
        else {
            return Err(Error::DecryptError);
        };
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..GCM_SALT_LEN].copy_from_slice(&self.salt);
        nonce[GCM_SALT_LEN..].copy_from_slice(&payload[..GCM_EXPLICIT_LEN]);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, text_len);
        let len = key
            .open(&nonce, &aad, &mut payload[GCM_EXPLICIT_LEN..])
            .map_err(|_| Error::DecryptError)?;
        if len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        Ok(msg
            .into_plain_message_range(GCM_EXPLICIT_LEN..GCM_EXPLICIT_LEN + len))
    }
}

/// ChaCha20-Poly1305: a full 12-byte IV from the key block, the
/// sequence number XORed in, nothing on the wire but ciphertext and
/// tag (RFC 7905).
struct ChaChaAead;

impl Tls12AeadAlgorithm for ChaChaAead {
    fn encrypter(
        &self,
        key: AeadKey,
        iv: &[u8],
        _: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(ChaChaProtection::new(key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(ChaChaProtection::new(key, iv))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: Algorithm::ChaCha20Poly1305.key_len(),
            fixed_iv_len: NONCE_LEN,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv: [u8; NONCE_LEN] =
            iv.try_into().map_err(|_| UnsupportedOperationError)?;
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::from(iv),
        })
    }
}

struct ChaChaProtection {
    key: Option<SealingKey>,
    iv: Iv,
}

impl ChaChaProtection {
    fn new(key: AeadKey, iv: &[u8]) -> Self {
        let iv: Option<[u8; NONCE_LEN]> = iv.try_into().ok();
        ChaChaProtection {
            key: iv.and(Algorithm::ChaCha20Poly1305.key(key.as_ref())),
            iv: Iv::from(iv.unwrap_or_default()),
        }
    }
}

impl MessageEncrypter for ChaChaProtection {
    fn encrypt<'a>(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let key = self.key.as_ref().ok_or(Error::EncryptError)?;
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut buf = EncryptBuffer::new(out, total)?;
        let nonce = Nonce::new(&self.iv, seq).to_array()?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        buf.extend_from_chunks(&msg.payload);
        let tag = key
            .seal(&nonce, &aad, buf.as_mut())
            .map_err(|_| Error::EncryptError)?;
        buf.extend_from_slice(&tag);
        Ok(EncodedMessage::new(
            msg.typ,
            msg.version,
            buf.into_written(),
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

impl MessageDecrypter for ChaChaProtection {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let key = self.key.as_ref().ok_or(Error::DecryptError)?;
        let payload = &mut msg.payload;
        let Some(text_len) = payload.len().checked_sub(TAG_LEN) else {
            return Err(Error::DecryptError);
        };
        let nonce = Nonce::new(&self.iv, seq).to_array()?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, text_len);
        let len = key
            .open(&nonce, &aad, payload)
            .map_err(|_| Error::DecryptError)?;
        if len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.truncate(len);
        Ok(msg.into_plain_message())
    }
}
