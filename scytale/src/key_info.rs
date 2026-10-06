//! What a key file holds, before it is read.
//!
//! Every key type reads its own DER and PEM and refuses anyone
//! else's as [`Error::WrongAlgorithm`]. A caller holding a file it
//! did not write has to know which type to hand it to, and asking
//! each in turn is slow and says nothing when they all decline.
//! [`KeyInfo`] reads the outer structure alone -- a PKCS#8
//! `PrivateKeyInfo`, a `SubjectPublicKeyInfo`, or the bare RSA and
//! EC forms that older tools write -- and names the algorithm and
//! which half of the pair it is. The key inside is not examined;
//! the type it names does that.

use zeroize::Zeroize;

use crate::Error;
use crate::codec::pem;
use crate::der::{self, Reader};
use crate::kem::ml_kem;
use crate::math::ec;
use crate::sig::{ml_dsa, slh_dsa};

/// The algorithm an encoded key is for.
///
/// This names the key, not its use: a [`P256`](Self::P256) key is
/// what both [`kex::ecdh::p256`](crate::kex::ecdh::p256) and
/// [`sig::ecdsa::p256`](crate::sig::ecdsa::p256) read, and an
/// [`Rsa`](Self::Rsa) key what [`pke::rsa`](crate::pke::rsa) and
/// [`sig::rsa`](crate::sig::rsa) both read. The type is
/// `non_exhaustive`: an algorithm the library gains later gains a
/// variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// RSA under `rsaEncryption`, usable for any RSA scheme.
    Rsa,
    /// RSA under `id-RSASSA-PSS`, restricted to PSS signatures.
    RsaPss,
    /// A key on P-256, for ECDH or ECDSA.
    P256,
    /// A key on P-384, for ECDH or ECDSA.
    P384,
    /// A key on P-521, for ECDH or ECDSA.
    P521,
    /// X25519.
    X25519,
    /// Ed25519.
    Ed25519,
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
    /// SLH-DSA-SHA2-128s.
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-128f.
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192s.
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-192f.
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256s.
    SlhDsaSha2_256s,
    /// SLH-DSA-SHA2-256f.
    SlhDsaSha2_256f,
    /// SLH-DSA-SHAKE-128s.
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f.
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-192s.
    SlhDsaShake192s,
    /// SLH-DSA-SHAKE-192f.
    SlhDsaShake192f,
    /// SLH-DSA-SHAKE-256s.
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f.
    SlhDsaShake256f,
}

impl Algorithm {
    /// The algorithm's name as its standard writes it.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Rsa => "RSA",
            Algorithm::RsaPss => "RSA-PSS",
            Algorithm::P256 => "P-256",
            Algorithm::P384 => "P-384",
            Algorithm::P521 => "P-521",
            Algorithm::X25519 => "X25519",
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::MlKem512 => "ML-KEM-512",
            Algorithm::MlKem768 => "ML-KEM-768",
            Algorithm::MlKem1024 => "ML-KEM-1024",
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
            Algorithm::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            Algorithm::SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
            Algorithm::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            Algorithm::SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
            Algorithm::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            Algorithm::SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
            Algorithm::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            Algorithm::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
            Algorithm::SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
            Algorithm::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
            Algorithm::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            Algorithm::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        }
    }

    /// The algorithm an AlgorithmIdentifier names, from its OID and
    /// parameters. One nobody here reads is [`Error::NotSupported`].
    fn from_identifier(algorithm: &der::Algorithm) -> Result<Self, Error> {
        let oid = algorithm.oid;
        if oid == der::RSA_ENCRYPTION {
            return Ok(Algorithm::Rsa);
        }
        if oid == der::RSASSA_PSS {
            return Ok(Algorithm::RsaPss);
        }
        if oid == ec::EC_PUBLIC_KEY {
            return Self::curve(Reader::new(algorithm.params).oid()?);
        }
        if oid == der::X25519 {
            return Ok(Algorithm::X25519);
        }
        if oid == der::ED25519 {
            return Ok(Algorithm::Ed25519);
        }
        // The NIST post-quantum algorithms sit under one arc each,
        // 2.16.840.1.101.3.4.4 for ML-KEM and .3 for the signatures,
        // with a final arc for the parameter set.
        let (prefix, arc) = match oid {
            [prefix @ .., arc] => (prefix, *arc),
            [] => return Err(Error::InvalidEncoding),
        };
        let found = if prefix == ml_kem::OID_PREFIX {
            match arc {
                1 => Algorithm::MlKem512,
                2 => Algorithm::MlKem768,
                3 => Algorithm::MlKem1024,
                _ => return Err(Error::NotSupported),
            }
        } else if prefix == ml_dsa::OID_PREFIX {
            debug_assert_eq!(ml_dsa::OID_PREFIX, slh_dsa::OID_PREFIX);
            match arc {
                17 => Algorithm::MlDsa44,
                18 => Algorithm::MlDsa65,
                19 => Algorithm::MlDsa87,
                20 => Algorithm::SlhDsaSha2_128s,
                21 => Algorithm::SlhDsaSha2_128f,
                22 => Algorithm::SlhDsaSha2_192s,
                23 => Algorithm::SlhDsaSha2_192f,
                24 => Algorithm::SlhDsaSha2_256s,
                25 => Algorithm::SlhDsaSha2_256f,
                26 => Algorithm::SlhDsaShake128s,
                27 => Algorithm::SlhDsaShake128f,
                28 => Algorithm::SlhDsaShake192s,
                29 => Algorithm::SlhDsaShake192f,
                30 => Algorithm::SlhDsaShake256s,
                31 => Algorithm::SlhDsaShake256f,
                _ => return Err(Error::NotSupported),
            }
        } else {
            return Err(Error::NotSupported);
        };
        Ok(found)
    }

    /// The curve a `namedCurve` OID names.
    fn curve(oid: &[u8]) -> Result<Self, Error> {
        if oid == ec::P256.oid {
            Ok(Algorithm::P256)
        } else if oid == ec::P384.oid {
            Ok(Algorithm::P384)
        } else if oid == ec::P521.oid {
            Ok(Algorithm::P521)
        } else {
            Err(Error::NotSupported)
        }
    }
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// What an encoded key is: its algorithm, and which half.
///
/// ```
/// use scytale::sig::ed25519;
/// use scytale::{Algorithm, KeyInfo};
///
/// # fn main() -> Result<(), scytale::Error> {
/// let secret = [7u8; ed25519::KEY_SIZE];
/// let pem = ed25519::secret_pem(&secret);
/// let info = KeyInfo::try_from_pem(&pem)?;
/// assert_eq!(info.algorithm, Algorithm::Ed25519);
/// assert!(info.private);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyInfo {
    /// The algorithm the key is for.
    pub algorithm: Algorithm,
    /// Whether it is the private half, as against the public.
    pub private: bool,
}

/// Room to decode any PEM block here: the largest key the library
/// writes, an expanded ML-DSA-87 private key, is under this.
const SCRATCH: usize = 8192;

impl KeyInfo {
    /// What a DER key is: a PKCS#8 `PrivateKeyInfo` (RFC 5958), a
    /// `SubjectPublicKeyInfo` (RFC 5280), an `RSAPrivateKey` or
    /// `RSAPublicKey` (RFC 8017), or an `ECPrivateKey` (RFC 5915)
    /// that names its curve. Anything else is
    /// [`Error::InvalidEncoding`]; an algorithm the library does
    /// not have is [`Error::NotSupported`]; a PKCS#8 version it does
    /// not read is [`Error::UnsupportedVersion`].
    pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
        if let Some(private) = rsa_pkcs1(der) {
            return Ok(KeyInfo {
                algorithm: Algorithm::Rsa,
                private,
            });
        }
        if let Some(algorithm) = ec_private_key(der)? {
            return Ok(KeyInfo {
                algorithm,
                private: true,
            });
        }
        match der::read_pkcs8(der) {
            Ok(info) => Ok(KeyInfo {
                algorithm: Algorithm::from_identifier(&info.algorithm)?,
                private: true,
            }),
            Err(Error::UnsupportedVersion) => Err(Error::UnsupportedVersion),
            Err(_) => {
                let (algorithm, _) = der::read_spki(der)?;
                Ok(KeyInfo {
                    algorithm: Algorithm::from_identifier(&algorithm)?,
                    private: false,
                })
            }
        }
    }

    /// [`try_from_der`](Self::try_from_der) through a PEM block. The
    /// label is read as well as the DER: `RSA PRIVATE KEY`, `RSA
    /// PUBLIC KEY` and `EC PRIVATE KEY` must hold the bare form they
    /// name, `PRIVATE KEY` and `PUBLIC KEY` the PKCS#8 and
    /// SubjectPublicKeyInfo forms, and any other label is
    /// [`Error::InvalidEncoding`].
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let mut der = [0u8; SCRATCH];
        let result = pem::decode(pem, &mut der)
            .map_err(|e| match e {
                Error::OutputTooSmall(_) => Error::InvalidEncoding,
                other => other,
            })
            .and_then(|(label, n)| {
                let der = &der[..n];
                const LABELS: [&str; 5] = [
                    "RSA PRIVATE KEY",
                    "RSA PUBLIC KEY",
                    "EC PRIVATE KEY",
                    "PRIVATE KEY",
                    "PUBLIC KEY",
                ];
                if !LABELS.contains(&label) {
                    return Err(Error::InvalidEncoding);
                }
                let info = Self::try_from_der(der)?;
                let expected = match label {
                    "RSA PRIVATE KEY" => rsa_pkcs1(der) == Some(true),
                    "RSA PUBLIC KEY" => rsa_pkcs1(der) == Some(false),
                    "EC PRIVATE KEY" => ec_private_key(der)?.is_some(),
                    "PRIVATE KEY" => {
                        info.private
                            && rsa_pkcs1(der).is_none()
                            && ec_private_key(der)?.is_none()
                    }
                    "PUBLIC KEY" => !info.private,
                    _ => false,
                };
                if expected {
                    Ok(info)
                } else {
                    Err(Error::InvalidEncoding)
                }
            });
        der.zeroize();
        result
    }
}

/// Whether `der` is a bare PKCS#1 structure, and which: an
/// `RSAPublicKey` is two integers, an `RSAPrivateKey` a version of
/// zero and eight more. Anything else is `None`, for the other
/// readers to try.
fn rsa_pkcs1(der: &[u8]) -> Option<bool> {
    let mut outer = Reader::new(der);
    let mut seq = outer.sequence().ok()?;
    outer.end().ok()?;
    let mut integers = 0;
    let mut first = None;
    while let Ok(n) = seq.integer() {
        if integers == 0 {
            first = Some(n);
        }
        integers += 1;
    }
    seq.end().ok()?;
    match (integers, first) {
        (2, _) => Some(false),
        (9, Some([0])) => Some(true),
        _ => None,
    }
}

/// The curve a bare `ECPrivateKey` names in its parameters, `None`
/// where `der` is not that structure. One that is, but names no
/// curve, cannot be placed and is refused; one that names a curve
/// the library lacks is [`Error::NotSupported`].
fn ec_private_key(der: &[u8]) -> Result<Option<Algorithm>, Error> {
    let mut outer = Reader::new(der);
    let Ok(mut seq) = outer.sequence() else {
        return Ok(None);
    };
    if outer.end().is_err() || seq.integer() != Ok(&[1][..]) {
        return Ok(None);
    }
    if seq.octet_string().is_err() {
        return Ok(None);
    }
    let Ok(params) = seq.optional(der::context(0)) else {
        return Ok(None);
    };
    match params {
        Some(params) => {
            let mut params = Reader::new(params);
            let oid = params.oid()?;
            params.end()?;
            Algorithm::curve(oid).map(Some)
        }
        None => Err(Error::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::random::CtrDrbg;
    use std::vec::Vec;

    fn info(der: &[u8]) -> (Algorithm, bool) {
        let info = KeyInfo::try_from_der(der).unwrap();
        (info.algorithm, info.private)
    }

    fn info_pem(pem: &[u8]) -> (Algorithm, bool) {
        let info = KeyInfo::try_from_pem(pem).unwrap();
        (info.algorithm, info.private)
    }

    #[test]
    fn curves_and_rsa() {
        let mut rng = CtrDrbg::from_system().unwrap();
        let mut out = [0u8; 4096];

        let secret = [7u8; 32];
        let der = crate::kex::x25519::secret_der(&secret);
        assert_eq!(info(&der), (Algorithm::X25519, true));
        let pem = crate::kex::x25519::secret_pem(&secret);
        assert_eq!(info_pem(&pem), (Algorithm::X25519, true));
        let public = crate::kex::x25519::public_key(&secret);
        let der = crate::kex::x25519::public_key_der(&public);
        assert_eq!(info(&der), (Algorithm::X25519, false));
        let pem = crate::kex::x25519::public_key_pem(&public);
        assert_eq!(info_pem(&pem), (Algorithm::X25519, false));

        let der = crate::sig::ed25519::secret_der(&secret);
        assert_eq!(info(&der), (Algorithm::Ed25519, true));
        let key =
            crate::sig::ed25519::PrivateKey::new(&crate::Key::from(secret));
        let der = key.public_key().der_bytes();
        assert_eq!(info(&der), (Algorithm::Ed25519, false));
        let pem = key.pem_bytes();
        assert_eq!(info_pem(&pem), (Algorithm::Ed25519, true));

        macro_rules! curve {
            ($module:path, $algorithm:expr) => {{
                use $module as m;
                let key = m::PrivateKey::generate(&mut rng).unwrap();
                let n = key.der_bytes(&mut out).unwrap();
                assert_eq!(info(&out[..n]), ($algorithm, true));
                let n = key.pem_bytes(&mut out).unwrap();
                assert_eq!(info_pem(&out[..n]), ($algorithm, true));
                let n = key.public_key().der_bytes(&mut out).unwrap();
                assert_eq!(info(&out[..n]), ($algorithm, false));
                let n = key.public_key().pem_bytes(&mut out).unwrap();
                assert_eq!(info_pem(&out[..n]), ($algorithm, false));
            }};
        }
        curve!(crate::kex::ecdh::p256, Algorithm::P256);
        curve!(crate::kex::ecdh::p384, Algorithm::P384);
        curve!(crate::kex::ecdh::p521, Algorithm::P521);
        curve!(crate::sig::ecdsa::p256, Algorithm::P256);

        let key =
            crate::sig::rsa::PrivateKey::generate(&mut rng, 1024).unwrap();
        let n = key.der_bytes(&mut out).unwrap();
        assert_eq!(info(&out[..n]), (Algorithm::Rsa, true));
        let n = key.pkcs1_bytes(&mut out).unwrap();
        assert_eq!(info(&out[..n]), (Algorithm::Rsa, true));
        let n = key.pkcs1_pem_bytes(&mut out).unwrap();
        assert!(out.starts_with(b"-----BEGIN RSA PRIVATE KEY-----"));
        assert_eq!(info_pem(&out[..n]), (Algorithm::Rsa, true));
        let n = key.pem_bytes(&mut out).unwrap();
        assert_eq!(info_pem(&out[..n]), (Algorithm::Rsa, true));
        let public = key.public_key();
        let n = public.der_bytes(&mut out).unwrap();
        assert_eq!(info(&out[..n]), (Algorithm::Rsa, false));
        let n = public.pkcs1_bytes(&mut out).unwrap();
        assert_eq!(info(&out[..n]), (Algorithm::Rsa, false));
        let n = public.pkcs1_pem_bytes(&mut out).unwrap();
        assert!(out.starts_with(b"-----BEGIN RSA PUBLIC KEY-----"));
        assert_eq!(info_pem(&out[..n]), (Algorithm::Rsa, false));
        let n = public.pem_bytes(&mut out).unwrap();
        assert_eq!(info_pem(&out[..n]), (Algorithm::Rsa, false));
    }

    #[test]
    fn post_quantum() {
        let mut rng = CtrDrbg::from_system().unwrap();
        let mut out = std::vec![0u8; 8192];
        macro_rules! set {
            ($module:path, $algorithm:expr) => {{
                use $module as m;
                let key = m::PrivateKey::generate(&mut rng).unwrap();
                let n = key.der_bytes(&mut out).unwrap();
                assert_eq!(info(&out[..n]), ($algorithm, true));
                let n = key.pem_bytes(&mut out).unwrap();
                assert_eq!(info_pem(&out[..n]), ($algorithm, true));
                let n = key.public_key().der_bytes(&mut out).unwrap();
                assert_eq!(info(&out[..n]), ($algorithm, false));
                let n = key.public_key().pem_bytes(&mut out).unwrap();
                assert_eq!(info_pem(&out[..n]), ($algorithm, false));
            }};
        }
        set!(crate::kem::ml_kem::ml_kem_512, Algorithm::MlKem512);
        set!(crate::kem::ml_kem::ml_kem_768, Algorithm::MlKem768);
        set!(crate::kem::ml_kem::ml_kem_1024, Algorithm::MlKem1024);
        set!(crate::sig::ml_dsa::ml_dsa_44, Algorithm::MlDsa44);
        set!(crate::sig::ml_dsa::ml_dsa_65, Algorithm::MlDsa65);
        set!(crate::sig::ml_dsa::ml_dsa_87, Algorithm::MlDsa87);
        set!(crate::sig::slh_dsa::sha2_128s, Algorithm::SlhDsaSha2_128s);
        set!(crate::sig::slh_dsa::sha2_128f, Algorithm::SlhDsaSha2_128f);
        set!(crate::sig::slh_dsa::sha2_192s, Algorithm::SlhDsaSha2_192s);
        set!(crate::sig::slh_dsa::sha2_192f, Algorithm::SlhDsaSha2_192f);
        set!(crate::sig::slh_dsa::sha2_256s, Algorithm::SlhDsaSha2_256s);
        set!(crate::sig::slh_dsa::sha2_256f, Algorithm::SlhDsaSha2_256f);
        set!(crate::sig::slh_dsa::shake_128s, Algorithm::SlhDsaShake128s);
        set!(crate::sig::slh_dsa::shake_128f, Algorithm::SlhDsaShake128f);
        set!(crate::sig::slh_dsa::shake_192s, Algorithm::SlhDsaShake192s);
        set!(crate::sig::slh_dsa::shake_192f, Algorithm::SlhDsaShake192f);
        set!(crate::sig::slh_dsa::shake_256s, Algorithm::SlhDsaShake256s);
        set!(crate::sig::slh_dsa::shake_256f, Algorithm::SlhDsaShake256f);
    }

    #[test]
    fn bare_ec_private_key() {
        // An RFC 5915 ECPrivateKey with its parameters, as
        // `openssl ec` writes: version 1, a 32-byte scalar, [0] the
        // curve, no public key.
        let mut der = Vec::new();
        der.extend_from_slice(&[0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20]);
        der.extend_from_slice(&[0x11; 32]);
        der.extend_from_slice(&[0xa0, 0x0a, 0x06, 0x08]);
        der.extend_from_slice(ec::P256.oid);
        assert_eq!(info(&der), (Algorithm::P256, true));
        let mut pem = std::vec![0u8; 256];
        let n = pem::encode("EC PRIVATE KEY", &der, &mut pem).unwrap();
        assert_eq!(info_pem(&pem[..n]), (Algorithm::P256, true));
        // Under the wrong label.
        let n = pem::encode("PRIVATE KEY", &der, &mut pem).unwrap();
        assert_eq!(
            KeyInfo::try_from_pem(&pem[..n]),
            Err(Error::InvalidEncoding)
        );
        // Without the parameters there is no saying which curve.
        assert_eq!(
            KeyInfo::try_from_der(&der[..39]).map(|_| ()),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn refuses_what_it_cannot_place() {
        // An unknown algorithm in a PKCS#8, an unknown curve, a
        // version 2 PKCS#8, an empty file, a certificate label.
        let unknown = [
            0x30, 0x0f, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x99, 0x04, 0x03, 0x01, 0x02, 0x03,
        ];
        assert_eq!(KeyInfo::try_from_der(&unknown), Err(Error::NotSupported));
        let spki = [
            0x30, 0x14, 0x30, 0x0c, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x01, 0x2b, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03,
        ];
        assert_eq!(KeyInfo::try_from_der(&spki), Err(Error::NotSupported));
        let mut v2 = unknown;
        v2[4] = 2;
        assert_eq!(KeyInfo::try_from_der(&v2), Err(Error::UnsupportedVersion));
        assert_eq!(KeyInfo::try_from_der(&[]), Err(Error::InvalidEncoding));
        let mut pem = [0u8; 128];
        let n = pem::encode("CERTIFICATE", &unknown, &mut pem).unwrap();
        assert_eq!(
            KeyInfo::try_from_pem(&pem[..n]),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(Algorithm::MlDsa65.name(), "ML-DSA-65");
    }
}
