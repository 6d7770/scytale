//! HPKE (RFC 9180), which rustls uses for Encrypted Client Hello.
//!
//! Each suite is a DHKEM with the KDF of its own hash and one of the
//! three AEADs; all of it is `scytale::pke::hpke`.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use rustls::Error;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeAead, HpkeKdf, HpkeKem, HpkeOpener,
    HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
    HpkeSymmetricCipherSuite,
};
use scytale::aead::{ChaCha20Poly1305, Gcm};
use scytale::cipher::aes::{Aes128, Aes256};
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::pke::hpke::{self, Cipher, Context, Kdf, TAG_SIZE};
use zeroize::Zeroize;

use crate::random::generator;

fn general(what: &str, e: scytale::Error) -> Error {
    Error::General(alloc::format!("HPKE {what}: {e}"))
}

/// Wrong-length key material from the peer or the caller.
fn bad_length(what: &str) -> Error {
    Error::General(alloc::format!("HPKE {what} is the wrong length"))
}

/// One suite: a KEM, by the marker type below, with a KDF and an
/// AEAD.
struct Suite<K, H, A> {
    suite: HpkeSuite,
    types: PhantomData<Types<K, H, A>>,
}

/// A suite's three choices, as types only; a function pointer, so
/// the suite is `Send` and `Sync` whatever they are.
type Types<K, H, A> = fn() -> (K, H, A);

impl<K, H, A> fmt::Debug for Suite<K, H, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Suite").field(&self.suite).finish()
    }
}

/// What a KEM brings: its keys from bytes, and the two halves of the
/// exchange. One marker type per KEM implements it.
trait Kem: Send + Sync + 'static {
    fn sender<H: Kdf, A: Cipher>(
        public: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, Context<H, A>), Error>;
    fn recipient<H: Kdf, A: Cipher>(
        secret: &[u8],
        enc: &[u8],
        info: &[u8],
    ) -> Result<Context<H, A>, Error>;
    fn generate() -> Result<(Vec<u8>, Vec<u8>), Error>;
}

/// DHKEM(X25519, HKDF-SHA256).
enum X25519 {}

impl Kem for X25519 {
    fn sender<H: Kdf, A: Cipher>(
        public: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, Context<H, A>), Error> {
        let public = public.try_into().map_err(|_| bad_length("public key"))?;
        let mut rng = generator().map_err(|e| general("randomness", e))?;
        let (enc, context) = hpke::x25519::PublicKey::new(public)
            .sender(&mut rng, info)
            .map_err(|e| general("encapsulation", e))?;
        Ok((enc.to_vec(), context))
    }

    fn recipient<H: Kdf, A: Cipher>(
        secret: &[u8],
        enc: &[u8],
        info: &[u8],
    ) -> Result<Context<H, A>, Error> {
        let secret = scytale::Key::try_from(secret)
            .map_err(|_| bad_length("private key"))?;
        let enc = enc.try_into().map_err(|_| bad_length("encapsulation"))?;
        hpke::x25519::PrivateKey::new(&secret)
            .recipient(enc, info)
            .map_err(|e| general("decapsulation", e))
    }

    fn generate() -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut rng = generator().map_err(|e| general("randomness", e))?;
        let key = hpke::x25519::PrivateKey::generate(&mut rng)
            .map_err(|e| general("key generation", e))?;
        let mut secret = key.secret_bytes();
        let pair = (key.public_key().bytes().to_vec(), secret.to_vec());
        secret.zeroize();
        Ok(pair)
    }
}

macro_rules! nist_kem {
    ($(#[$doc:meta])* $marker:ident, $module:ident) => {
        $(#[$doc])*
        enum $marker {}

        impl Kem for $marker {
            fn sender<H: Kdf, A: Cipher>(
                public: &[u8],
                info: &[u8],
            ) -> Result<(Vec<u8>, Context<H, A>), Error> {
                let public =
                    public.try_into().map_err(|_| bad_length("public key"))?;
                let public = hpke::$module::PublicKey::try_new(public)
                    .map_err(|e| general("public key", e))?;
                let mut rng =
                    generator().map_err(|e| general("randomness", e))?;
                let (enc, context) = public
                    .sender(&mut rng, info)
                    .map_err(|e| general("encapsulation", e))?;
                Ok((enc.to_vec(), context))
            }

            fn recipient<H: Kdf, A: Cipher>(
                secret: &[u8],
                enc: &[u8],
                info: &[u8],
            ) -> Result<Context<H, A>, Error> {
                let secret =
                    secret.try_into().map_err(|_| bad_length("private key"))?;
                let enc =
                    enc.try_into().map_err(|_| bad_length("encapsulation"))?;
                hpke::$module::PrivateKey::try_new(secret)
                    .and_then(|key| key.recipient(enc, info))
                    .map_err(|e| general("decapsulation", e))
            }

            fn generate() -> Result<(Vec<u8>, Vec<u8>), Error> {
                let mut rng =
                    generator().map_err(|e| general("randomness", e))?;
                let key = hpke::$module::PrivateKey::generate(&mut rng)
                    .map_err(|e| general("key generation", e))?;
                let mut secret = key.secret_bytes();
                let pair =
                    (key.public_key().bytes().to_vec(), secret.to_vec());
                secret.zeroize();
                Ok(pair)
            }
        }
    };
}

nist_kem!(
    /// DHKEM(P-256, HKDF-SHA256).
    P256, p256
);
nist_kem!(
    /// DHKEM(P-384, HKDF-SHA384).
    P384, p384
);
nist_kem!(
    /// DHKEM(P-521, HKDF-SHA512).
    P521, p521
);

impl<K, H, A> Hpke for Suite<K, H, A>
where
    K: Kem,
    H: Kdf + Send + Sync,
    A: Cipher + Send + Sync + 'static,
{
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        public: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sealer) = self.setup_sealer(info, public)?;
        Ok((enc, sealer.seal(aad, plaintext)?))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        public: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error>
    {
        let (enc, context) = K::sender::<H, A>(&public.0, info)?;
        Ok((EncapsulatedSecret(enc), Box::new(Sealing(context))))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        self.setup_opener(enc, info, secret)?.open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let context =
            K::recipient::<H, A>(secret.secret_bytes(), &enc.0, info)?;
        Ok(Box::new(Opening(context)))
    }

    fn generate_key_pair(
        &self,
    ) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (public, secret) = K::generate()?;
        Ok((HpkePublicKey(public), HpkePrivateKey::from(secret)))
    }

    fn suite(&self) -> HpkeSuite {
        self.suite
    }
}

/// A sender's context: each message is sealed under the next nonce.
struct Sealing<H: Kdf, A: Cipher>(Context<H, A>);

impl<H: Kdf, A: Cipher> fmt::Debug for Sealing<H, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealing").finish_non_exhaustive()
    }
}

impl<H, A> HpkeSealer for Sealing<H, A>
where
    H: Kdf + Send + Sync,
    A: Cipher + Send + Sync + 'static,
{
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_SIZE);
        out.extend_from_slice(plaintext);
        let mut tag = [0u8; TAG_SIZE];
        self.0
            .encrypt(aad, &mut out, &mut tag)
            .map_err(|e| general("seal", e))?;
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

/// A recipient's context.
struct Opening<H: Kdf, A: Cipher>(Context<H, A>);

impl<H: Kdf, A: Cipher> fmt::Debug for Opening<H, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opening").finish_non_exhaustive()
    }
}

impl<H, A> HpkeOpener for Opening<H, A>
where
    H: Kdf + Send + Sync,
    A: Cipher + Send + Sync + 'static,
{
    fn open(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let Some(len) = ciphertext.len().checked_sub(TAG_SIZE) else {
            return Err(Error::DecryptError);
        };
        let (body, tag) = ciphertext.split_at(len);
        let tag: &[u8; TAG_SIZE] =
            tag.try_into().map_err(|_| Error::DecryptError)?;
        let mut out = body.to_vec();
        self.0
            .decrypt(aad, &mut out, tag)
            .map_err(|_| Error::DecryptError)?;
        Ok(out)
    }
}

macro_rules! suite {
    (
        $(#[$doc:meta])* $name:ident, $kem:ident, $kem_id:ident,
        $hash:ty, $kdf_id:ident, $aead:ty, $aead_id:ident
    ) => {
        $(#[$doc])*
        pub static $name: &dyn Hpke = &Suite::<$kem, $hash, $aead> {
            suite: HpkeSuite {
                kem: HpkeKem::$kem_id,
                sym: HpkeSymmetricCipherSuite {
                    kdf_id: HpkeKdf::$kdf_id,
                    aead_id: HpkeAead::$aead_id,
                },
            },
            types: PhantomData,
        };
    };
}

macro_rules! kem_suites {
    (
        $kem:ident, $kem_id:ident, $hash:ty, $kdf_id:ident,
        $aes128:ident, $aes256:ident, $chacha:ident
    ) => {
        suite!(
            #[doc = concat!(stringify!($kem_id), " with AES-128-GCM.")]
            $aes128,
            $kem,
            $kem_id,
            $hash,
            $kdf_id,
            Gcm<Aes128>,
            AES_128_GCM
        );
        suite!(
            #[doc = concat!(stringify!($kem_id), " with AES-256-GCM.")]
            $aes256,
            $kem,
            $kem_id,
            $hash,
            $kdf_id,
            Gcm<Aes256>,
            AES_256_GCM
        );
        suite!(
            #[doc = concat!(stringify!($kem_id), " with ChaCha20-Poly1305.")]
            $chacha,
            $kem,
            $kem_id,
            $hash,
            $kdf_id,
            ChaCha20Poly1305,
            CHACHA20_POLY_1305
        );
    };
}

kem_suites!(
    X25519,
    DHKEM_X25519_HKDF_SHA256,
    Sha256,
    HKDF_SHA256,
    DH_KEM_X25519_HKDF_SHA256_AES_128,
    DH_KEM_X25519_HKDF_SHA256_AES_256,
    DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305
);
kem_suites!(
    P256,
    DHKEM_P256_HKDF_SHA256,
    Sha256,
    HKDF_SHA256,
    DH_KEM_P256_HKDF_SHA256_AES_128,
    DH_KEM_P256_HKDF_SHA256_AES_256,
    DH_KEM_P256_HKDF_SHA256_CHACHA20_POLY1305
);
kem_suites!(
    P384,
    DHKEM_P384_HKDF_SHA384,
    Sha384,
    HKDF_SHA384,
    DH_KEM_P384_HKDF_SHA384_AES_128,
    DH_KEM_P384_HKDF_SHA384_AES_256,
    DH_KEM_P384_HKDF_SHA384_CHACHA20_POLY1305
);
kem_suites!(
    P521,
    DHKEM_P521_HKDF_SHA512,
    Sha512,
    HKDF_SHA512,
    DH_KEM_P521_HKDF_SHA512_AES_128,
    DH_KEM_P521_HKDF_SHA512_AES_256,
    DH_KEM_P521_HKDF_SHA512_CHACHA20_POLY1305
);

/// Every suite here. X25519 first: it is the KEM ECH configurations
/// most often name.
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    DH_KEM_X25519_HKDF_SHA256_AES_128,
    DH_KEM_X25519_HKDF_SHA256_AES_256,
    DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
    DH_KEM_P256_HKDF_SHA256_AES_128,
    DH_KEM_P256_HKDF_SHA256_AES_256,
    DH_KEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
    DH_KEM_P384_HKDF_SHA384_AES_128,
    DH_KEM_P384_HKDF_SHA384_AES_256,
    DH_KEM_P384_HKDF_SHA384_CHACHA20_POLY1305,
    DH_KEM_P521_HKDF_SHA512_AES_128,
    DH_KEM_P521_HKDF_SHA512_AES_256,
    DH_KEM_P521_HKDF_SHA512_CHACHA20_POLY1305,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every suite seals and opens, single-shot and as a context;
    /// the wrong key, info or AAD fails.
    #[test]
    fn every_suite_round_trips() {
        for suite in ALL_SUPPORTED_SUITES {
            let (public, secret) = suite.generate_key_pair().unwrap();
            let (enc, sealed) =
                suite.seal(b"info", b"aad", b"message", &public).unwrap();
            let opened =
                suite.open(&enc, b"info", b"aad", &sealed, &secret).unwrap();
            assert_eq!(opened, b"message", "{:?}", suite.suite());
            assert!(
                suite.open(&enc, b"infO", b"aad", &sealed, &secret).is_err()
            );
            assert!(
                suite.open(&enc, b"info", b"aaD", &sealed, &secret).is_err()
            );
            let (_, other) = suite.generate_key_pair().unwrap();
            assert!(
                suite.open(&enc, b"info", b"aad", &sealed, &other).is_err()
            );

            let (enc, mut sealer) = suite.setup_sealer(b"i", &public).unwrap();
            let mut opener = suite.setup_opener(&enc, b"i", &secret).unwrap();
            for m in [&b"one"[..], b"two"] {
                let c = sealer.seal(b"", m).unwrap();
                assert_eq!(opener.open(b"", &c).unwrap(), m);
            }
            assert!(opener.open(b"", &[0; 15]).is_err());
        }
        assert_eq!(ALL_SUPPORTED_SUITES.len(), 12);
    }

    #[test]
    fn bad_lengths_are_refused() {
        let suite = DH_KEM_P256_HKDF_SHA256_AES_128;
        let short = HpkePublicKey(alloc::vec![4; 64]);
        assert!(suite.seal(b"", b"", b"m", &short).is_err());
        let (public, _) = suite.generate_key_pair().unwrap();
        let (enc, _) = suite.seal(b"", b"", b"m", &public).unwrap();
        let secret = HpkePrivateKey::from(alloc::vec![1; 31]);
        assert!(suite.setup_opener(&enc, b"", &secret).is_err());
    }
}
