//! Private keys, and the signatures a server or a client makes with
//! them in the handshake.

use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::Error;
use rustls::crypto::{KeyProvider, SignatureScheme, Signer, SigningKey};
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::sig::{ecdsa, ed25519, rsa};
use scytale::{Algorithm, KeyInfo};

use crate::random::generator;

/// The provider's key loader.
#[derive(Debug)]
pub(crate) struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(
        &self,
        der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, Error> {
        let key = match &der {
            PrivateKeyDer::Pkcs1(der) => rsa(der.secret_pkcs1_der())?,
            PrivateKeyDer::Sec1(der) => sec1(der.secret_sec1_der())?,
            PrivateKeyDer::Pkcs8(der) => pkcs8(der.secret_pkcs8_der())?,
            _ => return Err(refused("a key form", "not one rustls defines")),
        };
        Ok(Box::new(key))
    }
}

fn refused(what: &str, why: impl fmt::Display) -> Error {
    Error::General(format!("cannot load {what}: {why}"))
}

/// A bare `RSAPrivateKey`, the PKCS#1 form.
fn rsa(der: &[u8]) -> Result<Key, Error> {
    let key = rsa::PrivateKey::try_from_pkcs1(der)
        .map_err(|e| refused("RSA private key", e))?;
    Key::rsa(key)
}

/// A bare `ECPrivateKey`, the SEC 1 form. Its curve may be named
/// inside or left to the caller to know, so each curve is tried.
fn sec1(der: &[u8]) -> Result<Key, Error> {
    if let Ok(key) = ecdsa::p256::PrivateKey::try_from_sec1_der(der) {
        return Key::p256(key);
    }
    if let Ok(key) = ecdsa::p384::PrivateKey::try_from_sec1_der(der) {
        return Key::p384(key);
    }
    match ecdsa::p521::PrivateKey::try_from_sec1_der(der) {
        Ok(key) => Key::p521(key),
        Err(e) => Err(refused("SEC 1 private key", e)),
    }
}

/// A PKCS#8 `PrivateKeyInfo`, whose algorithm identifier says which
/// key it holds.
fn pkcs8(der: &[u8]) -> Result<Key, Error> {
    let info =
        KeyInfo::try_from_der(der).map_err(|e| refused("PKCS#8 key", e))?;
    let what = info.algorithm.name();
    let load = |e| refused(what, e);
    match info.algorithm {
        Algorithm::Rsa => rsa::PrivateKey::try_from_der(der)
            .map_err(load)
            .and_then(Key::rsa),
        // An `id-RSASSA-PSS` key's certificate carries PSS parameters
        // this provider does not reproduce, and rustls compares the
        // two byte for byte; an `rsaEncryption` key signs PSS anyway.
        Algorithm::RsaPss => {
            Err(refused(what, "only rsaEncryption keys are taken"))
        }
        Algorithm::P256 => ecdsa::p256::PrivateKey::try_from_der(der)
            .map_err(load)
            .and_then(Key::p256),
        Algorithm::P384 => ecdsa::p384::PrivateKey::try_from_der(der)
            .map_err(load)
            .and_then(Key::p384),
        Algorithm::P521 => ecdsa::p521::PrivateKey::try_from_der(der)
            .map_err(load)
            .and_then(Key::p521),
        Algorithm::Ed25519 => ed25519::PrivateKey::try_from_der(der)
            .map_err(load)
            .map(Key::ed25519),
        _ => Err(refused(what, "not a signature algorithm TLS uses here")),
    }
}

/// The RSA moduli accepted for signing, as for verifying.
const RSA_BITS: core::ops::RangeInclusive<usize> = 2048..=8192;

/// The RSA schemes, in the order a key prefers them: PSS before
/// PKCS#1 v1.5, longer hashes first.
static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// A loaded key: the secret, shared with each signer it hands out,
/// and its public half encoded as the certificate's
/// `SubjectPublicKeyInfo` should be.
pub(crate) struct Key {
    secret: Secret,
    spki: Vec<u8>,
}

#[derive(Clone)]
enum Secret {
    Rsa(Arc<rsa::PrivateKey>),
    P256(Arc<ecdsa::p256::PrivateKey>),
    P384(Arc<ecdsa::p384::PrivateKey>),
    P521(Arc<ecdsa::p521::PrivateKey>),
    Ed25519(Arc<ed25519::PrivateKey>),
}

/// The SPKI scytale writes, into a vector of the length it reports.
fn spki(
    write: impl Fn(&mut [u8]) -> Result<usize, scytale::Error>,
    room: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; room];
    let n = write(&mut out).map_err(|e| refused("a public key", e))?;
    out.truncate(n);
    Ok(out)
}

impl Key {
    fn rsa(key: rsa::PrivateKey) -> Result<Self, Error> {
        if !RSA_BITS.contains(&key.bits()) {
            return Err(refused(
                "RSA private key",
                format!("{} bits, outside 2048 to 8192", key.bits()),
            ));
        }
        let public = key.public_key();
        let spki = spki(|o| public.der_bytes(o), 2 * key.modulus_len() + 64)?;
        Ok(Key {
            secret: Secret::Rsa(Arc::new(key)),
            spki,
        })
    }

    fn p256(key: ecdsa::p256::PrivateKey) -> Result<Self, Error> {
        let spki = spki(
            |o| key.public_key().der_bytes(o),
            ecdsa::p256::PUBLIC_KEY_DER_SIZE,
        )?;
        Ok(Key {
            secret: Secret::P256(Arc::new(key)),
            spki,
        })
    }

    fn p384(key: ecdsa::p384::PrivateKey) -> Result<Self, Error> {
        let spki = spki(
            |o| key.public_key().der_bytes(o),
            ecdsa::p384::PUBLIC_KEY_DER_SIZE,
        )?;
        Ok(Key {
            secret: Secret::P384(Arc::new(key)),
            spki,
        })
    }

    fn p521(key: ecdsa::p521::PrivateKey) -> Result<Self, Error> {
        let spki = spki(
            |o| key.public_key().der_bytes(o),
            ecdsa::p521::PUBLIC_KEY_DER_SIZE,
        )?;
        Ok(Key {
            secret: Secret::P521(Arc::new(key)),
            spki,
        })
    }

    fn ed25519(key: ed25519::PrivateKey) -> Self {
        let spki = key.public_key().der_bytes().to_vec();
        Key {
            secret: Secret::Ed25519(Arc::new(key)),
            spki,
        }
    }

    /// The schemes this key can sign under, best first.
    fn schemes(&self) -> &'static [SignatureScheme] {
        match self.secret {
            Secret::Rsa(_) => RSA_SCHEMES,
            Secret::P256(_) => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Secret::P384(_) => &[SignatureScheme::ECDSA_NISTP384_SHA384],
            Secret::P521(_) => &[SignatureScheme::ECDSA_NISTP521_SHA512],
            Secret::Ed25519(_) => &[SignatureScheme::ED25519],
        }
    }

    fn algorithm(&self) -> &'static str {
        match self.secret {
            Secret::Rsa(_) => "RSA",
            Secret::P256(_) => "ECDSA P-256",
            Secret::P384(_) => "ECDSA P-384",
            Secret::P521(_) => "ECDSA P-521",
            Secret::Ed25519(_) => "Ed25519",
        }
    }
}

/// The algorithm only: never the key.
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

impl SigningKey for Key {
    fn choose_scheme(
        &self,
        offered: &[SignatureScheme],
    ) -> Option<Box<dyn Signer>> {
        let scheme = self
            .schemes()
            .iter()
            .find(|scheme| offered.contains(scheme))?;
        Some(Box::new(Signing {
            secret: self.secret.clone(),
            scheme: *scheme,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(&self.spki[..]))
    }
}

/// One signature, under one scheme.
struct Signing {
    secret: Secret,
    scheme: SignatureScheme,
}

impl fmt::Debug for Signing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signing")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

/// An ECDSA signature in the DER form TLS carries.
fn ecdsa_der(
    raw: &[u8],
    der: impl Fn(&mut [u8]) -> Result<usize, scytale::Error>,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; raw.len() + 9];
    let n = der(&mut out).map_err(failed)?;
    out.truncate(n);
    Ok(out)
}

fn failed(e: scytale::Error) -> Error {
    Error::General(format!("signing failed: {e}"))
}

impl Signer for Signing {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
        use SignatureScheme as S;
        match (&self.secret, self.scheme) {
            (Secret::Rsa(key), S::RSA_PKCS1_SHA256) => {
                rsa_bytes(key.sign_pkcs1::<Sha256>(message))
            }
            (Secret::Rsa(key), S::RSA_PKCS1_SHA384) => {
                rsa_bytes(key.sign_pkcs1::<Sha384>(message))
            }
            (Secret::Rsa(key), S::RSA_PKCS1_SHA512) => {
                rsa_bytes(key.sign_pkcs1::<Sha512>(message))
            }
            // PSS takes a salt of the digest's length, drawn fresh.
            (Secret::Rsa(key), S::RSA_PSS_SHA256) => {
                let mut rng = generator().map_err(failed)?;
                rsa_bytes(key.sign_pss::<Sha256, _>(&mut rng, message))
            }
            (Secret::Rsa(key), S::RSA_PSS_SHA384) => {
                let mut rng = generator().map_err(failed)?;
                rsa_bytes(key.sign_pss::<Sha384, _>(&mut rng, message))
            }
            (Secret::Rsa(key), S::RSA_PSS_SHA512) => {
                let mut rng = generator().map_err(failed)?;
                rsa_bytes(key.sign_pss::<Sha512, _>(&mut rng, message))
            }
            // The nonce is RFC 6979's, derived from the key and the
            // digest: no randomness to fail or to leak.
            (Secret::P256(key), S::ECDSA_NISTP256_SHA256) => {
                let sig = key.sign::<Sha256>(message).map_err(failed)?;
                ecdsa_der(&sig, |o| ecdsa::p256::signature_der(&sig, o))
            }
            (Secret::P384(key), S::ECDSA_NISTP384_SHA384) => {
                let sig = key.sign::<Sha384>(message).map_err(failed)?;
                ecdsa_der(&sig, |o| ecdsa::p384::signature_der(&sig, o))
            }
            (Secret::P521(key), S::ECDSA_NISTP521_SHA512) => {
                let sig = key.sign::<Sha512>(message).map_err(failed)?;
                ecdsa_der(&sig, |o| ecdsa::p521::signature_der(&sig, o))
            }
            (Secret::Ed25519(key), S::ED25519) => {
                Ok(key.sign(message).to_vec())
            }
            // `choose_scheme` hands out only the pairs above.
            (_, scheme) => Err(Error::General(format!(
                "no {scheme:?} signature from this key"
            ))),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn rsa_bytes(
    signature: Result<rsa::Signature, scytale::Error>,
) -> Result<Vec<u8>, Error> {
    Ok(signature.map_err(failed)?.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};

    fn pkcs8(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec()))
    }

    const RSA_2048: &[u8] =
        include_bytes!("../tests/data/rsa-2048/end.pkcs8.der");
    const P256: &[u8] =
        include_bytes!("../tests/data/ecdsa-p256/end.pkcs8.der");

    #[test]
    fn rsa_prefers_pss_and_longer_hashes() {
        let key = Keys.load_private_key(pkcs8(RSA_2048)).unwrap();
        let all = RSA_SCHEMES;
        assert_eq!(
            key.choose_scheme(all).unwrap().scheme(),
            SignatureScheme::RSA_PSS_SHA512
        );
        let pkcs1 = [SignatureScheme::RSA_PKCS1_SHA256];
        assert_eq!(
            key.choose_scheme(&pkcs1).unwrap().scheme(),
            SignatureScheme::RSA_PKCS1_SHA256
        );
        assert!(key.choose_scheme(&[SignatureScheme::ED25519]).is_none());
        // A modulus' worth of bytes, under each scheme.
        for scheme in RSA_SCHEMES {
            let signer = key.choose_scheme(&[*scheme]).unwrap();
            assert_eq!(signer.sign(b"message").unwrap().len(), 256);
        }
    }

    #[test]
    fn ecdsa_signs_under_its_curve_only() {
        let key = Keys.load_private_key(pkcs8(P256)).unwrap();
        assert!(
            key.choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_none()
        );
        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();
        // DER: a SEQUENCE of two INTEGERs.
        let signature = signer.sign(b"message").unwrap();
        assert_eq!(signature[0], 0x30);
        assert!(signature.len() <= 72);
    }

    /// The public key is the certificate's SPKI, byte for byte, which
    /// is what rustls checks a key against its certificate with.
    #[test]
    fn public_key_matches_the_certificate() {
        let cert = include_bytes!("../tests/data/ecdsa-p256/end.der");
        let key = Keys.load_private_key(pkcs8(P256)).unwrap();
        let spki = key.public_key().unwrap();
        let spki = spki.as_ref();
        assert!(cert.windows(spki.len()).any(|w| w == spki));
    }

    #[test]
    fn debug_shows_no_key() {
        let key = Keys.load_private_key(pkcs8(P256)).unwrap();
        assert_eq!(
            alloc::format!("{key:?}"),
            "Key { algorithm: \"ECDSA P-256\", .. }"
        );
    }

    #[test]
    fn refusals() {
        // An RSA key below 2048 bits.
        let mut rng = generator().unwrap();
        let small = rsa::PrivateKey::generate(&mut rng, 1024).unwrap();
        let mut der = vec![0u8; 2048];
        let n = small.der_bytes(&mut der).unwrap();
        assert!(Keys.load_private_key(pkcs8(&der[..n])).is_err());
        // An X25519 key, which signs nothing.
        let x = scytale::kex::x25519::PrivateKey::generate(&mut rng).unwrap();
        assert!(Keys.load_private_key(pkcs8(&x.der_bytes())).is_err());
        // Bytes that are no key at all, in each form.
        assert!(Keys.load_private_key(pkcs8(&[0x30, 0x00])).is_err());
        let junk = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(vec![1, 2]));
        assert!(Keys.load_private_key(junk).is_err());
    }
}
