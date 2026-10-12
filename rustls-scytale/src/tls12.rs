//! The TLS 1.2 cipher suites and their record protection
//! (RFC 5288 for AES-GCM, RFC 7905 for ChaCha20-Poly1305, RFC 7251
//! for AES-CCM).

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

// RFC 7251 defines AES-CCM for ECDHE_ECDSA only, every one with the
// SHA-256 PRF. CCM runs AES twice per block, so the bound that gives
// AES-GCM 2^24 full records gives CCM 2^23.
suite!(
    /// TLS_ECDHE_ECDSA_WITH_AES_128_CCM.
    ///
    /// In [`ALL_TLS12_CIPHER_SUITES`](crate::ALL_TLS12_CIPHER_SUITES)
    /// but not the defaults: nothing on the open web negotiates it;
    /// it is for the constrained-device profiles that ask for AES-CCM.
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    SHA256, PRF_SHA256, ECDSA_SCHEMES, AES_128_CCM, 1 << 23
);
suite!(
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CCM.
    ///
    /// In [`ALL_TLS12_CIPHER_SUITES`](crate::ALL_TLS12_CIPHER_SUITES)
    /// but not the defaults, as the 128-bit form.
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    SHA256, PRF_SHA256, ECDSA_SCHEMES, AES_256_CCM, 1 << 23
);
suite!(
    /// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: AES-128-CCM with an 8-byte
    /// tag, as IEEE 2030.5 and RFC 7925 require.
    ///
    /// A forgery succeeds with probability 2^-64 a try rather than
    /// 2^-128, the trade those profiles make for eight bytes a
    /// record; TLS ends the connection at the first failure, so tries
    /// do not accumulate under one key.
    ///
    /// Neither in the defaults nor in
    /// [`ALL_TLS12_CIPHER_SUITES`](crate::ALL_TLS12_CIPHER_SUITES): a
    /// provider offers or accepts it only where a program names it.
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    SHA256, PRF_SHA256, ECDSA_SCHEMES, AES_128_CCM_8, 1 << 23
);
suite!(
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: AES-256-CCM with an 8-byte
    /// tag.
    ///
    /// The tag, not the key, bounds a forgery: 2^-64 a try, as for
    /// [`TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8`]. Neither in the defaults
    /// nor in
    /// [`ALL_TLS12_CIPHER_SUITES`](crate::ALL_TLS12_CIPHER_SUITES).
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    SHA256, PRF_SHA256, ECDSA_SCHEMES, AES_256_CCM_8, 1 << 23
);

static AES_128_GCM: SaltedAead = SaltedAead(Algorithm::Aes128Gcm);
static AES_256_GCM: SaltedAead = SaltedAead(Algorithm::Aes256Gcm);
static AES_128_CCM: SaltedAead = SaltedAead(Algorithm::Aes128Ccm);
static AES_256_CCM: SaltedAead = SaltedAead(Algorithm::Aes256Ccm);
static AES_128_CCM_8: SaltedAead = SaltedAead(Algorithm::Aes128Ccm8);
static AES_256_CCM_8: SaltedAead = SaltedAead(Algorithm::Aes256Ccm8);
static CHACHA20_POLY1305: ChaChaAead = ChaChaAead;

/// The salt from the key block, and the explicit part of the nonce
/// that travels with each record.
const SALT_LEN: usize = 4;
const EXPLICIT_LEN: usize = 8;

/// AES-GCM and AES-CCM, whose nonces are laid out alike: a salt from
/// the key block and an explicit part sent with each record (RFC
/// 5288, RFC 6655). The RFCs leave the explicit part's construction
/// to the sender; this one starts from eight more bytes of key block
/// and XORs the sequence number in, as TLS 1.3 does, so it never
/// repeats under one key and says nothing a counter would not.
struct SaltedAead(Algorithm);

impl SaltedAead {
    /// The salt and the starting explicit part, as one 12-byte IV;
    /// `None` if rustls handed over parts of other lengths.
    fn iv(salt: &[u8], explicit: &[u8]) -> Option<Iv> {
        if salt.len() != SALT_LEN || explicit.len() != EXPLICIT_LEN {
            return None;
        }
        let mut iv = [0u8; NONCE_LEN];
        iv[..SALT_LEN].copy_from_slice(salt);
        iv[SALT_LEN..].copy_from_slice(explicit);
        Some(Iv::from(iv))
    }
}

impl Tls12AeadAlgorithm for SaltedAead {
    fn encrypter(
        &self,
        key: AeadKey,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        let iv = Self::iv(iv, extra);
        Box::new(SaltedEncrypter {
            key: iv.as_ref().and(self.0.key(key.as_ref())),
            iv: iv.unwrap_or_default(),
            tag_len: self.0.tag_len(),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let salt: Option<[u8; SALT_LEN]> = iv.try_into().ok();
        Box::new(SaltedDecrypter {
            key: salt.and(self.0.key(key.as_ref())),
            salt: salt.unwrap_or_default(),
            tag_len: self.0.tag_len(),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0.key_len(),
            fixed_iv_len: SALT_LEN,
            explicit_nonce_len: EXPLICIT_LEN,
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
            // ChaCha20-Poly1305 is not this type's, and rustls has no
            // form for CCM keys to be handed on in.
            Algorithm::ChaCha20Poly1305
            | Algorithm::Aes128Ccm
            | Algorithm::Aes256Ccm
            | Algorithm::Aes128Ccm8
            | Algorithm::Aes256Ccm8 => Err(UnsupportedOperationError),
        }
    }
}

struct SaltedEncrypter {
    key: Option<SealingKey>,
    iv: Iv,
    tag_len: usize,
}

impl MessageEncrypter for SaltedEncrypter {
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
        buf.extend_from_slice(&nonce[SALT_LEN..]);
        buf.extend_from_chunks(&msg.payload);
        let tag = key
            .seal(&nonce, &aad, &mut buf.as_mut()[EXPLICIT_LEN..])
            .map_err(|_| Error::EncryptError)?;
        buf.extend_from_slice(tag.as_ref());
        Ok(EncodedMessage::new(
            msg.typ,
            msg.version,
            buf.into_written(),
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        EXPLICIT_LEN + payload_len + self.tag_len
    }
}

struct SaltedDecrypter {
    key: Option<SealingKey>,
    salt: [u8; SALT_LEN],
    tag_len: usize,
}

impl MessageDecrypter for SaltedDecrypter {
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
            payload.len().checked_sub(EXPLICIT_LEN + self.tag_len)
        else {
            return Err(Error::DecryptError);
        };
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..SALT_LEN].copy_from_slice(&self.salt);
        nonce[SALT_LEN..].copy_from_slice(&payload[..EXPLICIT_LEN]);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, text_len);
        let len = key
            .open(&nonce, &aad, &mut payload[EXPLICIT_LEN..])
            .map_err(|_| Error::DecryptError)?;
        if len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        Ok(msg.into_plain_message_range(EXPLICIT_LEN..EXPLICIT_LEN + len))
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
        buf.extend_from_slice(tag.as_ref());
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
