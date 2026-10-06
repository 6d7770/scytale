//! Signature verification, for certificate chains and for the
//! handshake's own signatures.
//!
//! Each algorithm is a pair of algorithm identifiers, which is how
//! webpki matches one to a certificate, and a check. The public key
//! arrives as the contents of the certificate's `subjectPublicKey`
//! bit string: an uncompressed point, an `RSAPublicKey`, or 32 raw
//! bytes for Ed25519.

use core::fmt;

use pki_types::alg_id;
use pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use rustls::crypto::{SignatureScheme, WebPkiSupportedAlgorithms};
use scytale::hash::Hash;
use scytale::hash::sha2::{Sha256, Sha384, Sha512};
use scytale::sig::rsa::DigestInfo;
use scytale::sig::{ecdsa, ed25519, rsa};

/// One verification algorithm.
struct Algorithm {
    name: &'static str,
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    check: fn(&[u8], &[u8], &[u8]) -> bool,
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match (self.check)(public_key, message, signature) {
            true => Ok(()),
            false => Err(InvalidSignature),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

/// ECDSA over each curve: an uncompressed point, a DER signature.
macro_rules! ecdsa_check {
    ($fn:ident, $curve:ident) => {
        fn $fn<H: Hash + Default>(
            key: &[u8],
            message: &[u8],
            sig: &[u8],
        ) -> bool {
            if key.len() != ecdsa::$curve::PUBLIC_KEY_SIZE
                || key.first() != Some(&0x04)
            {
                return false;
            }
            let (Ok(key), Ok(sig)) = (
                ecdsa::$curve::PublicKey::try_from_sec1(key),
                ecdsa::$curve::signature_from_der(sig),
            ) else {
                return false;
            };
            key.verify::<H>(message, &sig).is_ok()
        }
    };
}

ecdsa_check!(ecdsa_p256, p256);
ecdsa_check!(ecdsa_p384, p384);
ecdsa_check!(ecdsa_p521, p521);

fn ed25519(key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (key.try_into(), sig.try_into()) else {
        return false;
    };
    ed25519::verify(key, message, sig).is_ok()
}

/// The RSA moduli accepted: below 2048 bits is too weak to take, and
/// above 8192 is past what scytale reads.
const RSA_BITS: core::ops::RangeInclusive<usize> = 2048..=8192;

fn rsa_key(key: &[u8]) -> Option<rsa::PublicKey> {
    let key = rsa::PublicKey::try_from_pkcs1(key).ok()?;
    RSA_BITS.contains(&key.bits()).then_some(key)
}

fn rsa_pkcs1<H: DigestInfo + Default>(
    key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    rsa_key(key).is_some_and(|k| k.verify_pkcs1::<H>(message, sig).is_ok())
}

/// PSS with MGF1 over the same hash and a salt of the digest's
/// length, which TLS 1.3 requires and these identifiers name.
fn rsa_pss<H: Hash + Default>(key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    rsa_key(key).is_some_and(|k| k.verify_pss::<H>(message, sig).is_ok())
}

/// The PKCS#1 v1.5 signature identifiers with their parameters left
/// out, which RFC 4055 section 5 says must be accepted though NULL is
/// what should be written.
const RSA_PKCS1_SHA256_ABSENT_PARAMS: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    ]);
const RSA_PKCS1_SHA384_ABSENT_PARAMS: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
    ]);
const RSA_PKCS1_SHA512_ABSENT_PARAMS: AlgorithmIdentifier =
    AlgorithmIdentifier::from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
    ]);

macro_rules! algorithm {
    (
        $(#[$doc:meta])* $name:ident, $public:expr, $signature:expr,
        $check:expr
    ) => {
        $(#[$doc])*
        pub static $name: &dyn SignatureVerificationAlgorithm = &Algorithm {
            name: stringify!($name),
            public_key: $public,
            signature: $signature,
            check: $check,
        };
    };
}

algorithm!(
    /// ECDSA on P-256 with SHA-256.
    ECDSA_P256_SHA256, alg_id::ECDSA_P256, alg_id::ECDSA_SHA256,
    ecdsa_p256::<Sha256>
);
algorithm!(
    /// ECDSA on P-256 with SHA-384.
    ECDSA_P256_SHA384, alg_id::ECDSA_P256, alg_id::ECDSA_SHA384,
    ecdsa_p256::<Sha384>
);
algorithm!(
    /// ECDSA on P-256 with SHA-512.
    ECDSA_P256_SHA512, alg_id::ECDSA_P256, alg_id::ECDSA_SHA512,
    ecdsa_p256::<Sha512>
);
algorithm!(
    /// ECDSA on P-384 with SHA-256.
    ECDSA_P384_SHA256, alg_id::ECDSA_P384, alg_id::ECDSA_SHA256,
    ecdsa_p384::<Sha256>
);
algorithm!(
    /// ECDSA on P-384 with SHA-384.
    ECDSA_P384_SHA384, alg_id::ECDSA_P384, alg_id::ECDSA_SHA384,
    ecdsa_p384::<Sha384>
);
algorithm!(
    /// ECDSA on P-384 with SHA-512.
    ECDSA_P384_SHA512, alg_id::ECDSA_P384, alg_id::ECDSA_SHA512,
    ecdsa_p384::<Sha512>
);
algorithm!(
    /// ECDSA on P-521 with SHA-256.
    ECDSA_P521_SHA256, alg_id::ECDSA_P521, alg_id::ECDSA_SHA256,
    ecdsa_p521::<Sha256>
);
algorithm!(
    /// ECDSA on P-521 with SHA-384.
    ECDSA_P521_SHA384, alg_id::ECDSA_P521, alg_id::ECDSA_SHA384,
    ecdsa_p521::<Sha384>
);
algorithm!(
    /// ECDSA on P-521 with SHA-512.
    ECDSA_P521_SHA512, alg_id::ECDSA_P521, alg_id::ECDSA_SHA512,
    ecdsa_p521::<Sha512>
);
algorithm!(
    /// Ed25519.
    ED25519, alg_id::ED25519, alg_id::ED25519, ed25519
);
algorithm!(
    /// RSA PKCS#1 v1.5 with SHA-256, 2048 to 8192 bits.
    RSA_PKCS1_2048_8192_SHA256, alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA256, rsa_pkcs1::<Sha256>
);
algorithm!(
    /// RSA PKCS#1 v1.5 with SHA-384, 2048 to 8192 bits.
    RSA_PKCS1_2048_8192_SHA384, alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA384, rsa_pkcs1::<Sha384>
);
algorithm!(
    /// RSA PKCS#1 v1.5 with SHA-512, 2048 to 8192 bits.
    RSA_PKCS1_2048_8192_SHA512, alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA512, rsa_pkcs1::<Sha512>
);
algorithm!(
    /// As [`RSA_PKCS1_2048_8192_SHA256`], the signature's parameters
    /// absent.
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS, alg_id::RSA_ENCRYPTION,
    RSA_PKCS1_SHA256_ABSENT_PARAMS, rsa_pkcs1::<Sha256>
);
algorithm!(
    /// As [`RSA_PKCS1_2048_8192_SHA384`], the signature's parameters
    /// absent.
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS, alg_id::RSA_ENCRYPTION,
    RSA_PKCS1_SHA384_ABSENT_PARAMS, rsa_pkcs1::<Sha384>
);
algorithm!(
    /// As [`RSA_PKCS1_2048_8192_SHA512`], the signature's parameters
    /// absent.
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS, alg_id::RSA_ENCRYPTION,
    RSA_PKCS1_SHA512_ABSENT_PARAMS, rsa_pkcs1::<Sha512>
);
algorithm!(
    /// RSA-PSS with SHA-256 on an `rsaEncryption` key, 2048 to 8192
    /// bits.
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA256, rsa_pss::<Sha256>
);
algorithm!(
    /// RSA-PSS with SHA-384 on an `rsaEncryption` key.
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY, alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA384, rsa_pss::<Sha384>
);
algorithm!(
    /// RSA-PSS with SHA-512 on an `rsaEncryption` key.
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY, alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PSS_SHA512, rsa_pss::<Sha512>
);

/// Every verification algorithm here, for certificate chains.
pub static ALL_VERIFICATION_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P256_SHA512,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    ECDSA_P384_SHA512,
    ECDSA_P521_SHA256,
    ECDSA_P521_SHA384,
    ECDSA_P521_SHA512,
    ED25519,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// The algorithms each handshake signature scheme may be checked
/// with, in preference order: that order is what the peer is told.
/// TLS 1.3 ties an ECDSA scheme to its curve and checks the first
/// entry only; TLS 1.2 does not, and tries each.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms =
    match WebPkiSupportedAlgorithms::new(
        ALL_VERIFICATION_ALGS,
        &[
            (
                SignatureScheme::ECDSA_NISTP384_SHA384,
                &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ECDSA_P521_SHA384],
            ),
            (
                SignatureScheme::ECDSA_NISTP256_SHA256,
                &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P521_SHA256],
            ),
            (
                SignatureScheme::ECDSA_NISTP521_SHA512,
                &[ECDSA_P521_SHA512, ECDSA_P384_SHA512, ECDSA_P256_SHA512],
            ),
            (SignatureScheme::ED25519, &[ED25519]),
            (
                SignatureScheme::RSA_PSS_SHA512,
                &[RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PSS_SHA384,
                &[RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PSS_SHA256,
                &[RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA512,
                &[RSA_PKCS1_2048_8192_SHA512],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA384,
                &[RSA_PKCS1_2048_8192_SHA384],
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA256,
                &[RSA_PKCS1_2048_8192_SHA256],
            ),
        ],
    ) {
        Ok(algorithms) => algorithms,
        // Checked when the crate is built: the lists above are
        // constants and are not empty.
        Err(_) => panic!("empty signature algorithm mapping"),
    };

#[cfg(test)]
mod tests {
    use super::*;
    use scytale::random::CtrDrbg;

    #[test]
    fn absent_params_are_the_null_forms_without_the_null() {
        for (with, without) in [
            (alg_id::RSA_PKCS1_SHA256, RSA_PKCS1_SHA256_ABSENT_PARAMS),
            (alg_id::RSA_PKCS1_SHA384, RSA_PKCS1_SHA384_ABSENT_PARAMS),
            (alg_id::RSA_PKCS1_SHA512, RSA_PKCS1_SHA512_ABSENT_PARAMS),
        ] {
            let with = with.as_ref();
            assert_eq!(&with[with.len() - 2..], [0x05, 0x00]);
            assert_eq!(&with[..with.len() - 2], without.as_ref());
        }
    }

    /// A signature made here checks, and fails on another message;
    /// the same key compressed is refused, since certificates carry
    /// uncompressed points.
    #[test]
    fn ecdsa_round_trip_and_compressed_keys() {
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = ecdsa::p384::PrivateKey::generate(&mut rng).unwrap();
        let sig = key.sign::<Sha384>(b"message").unwrap();
        let mut der = [0u8; 120];
        let n = ecdsa::p384::signature_der(&sig, &mut der).unwrap();
        let public = key.public_key().sec1_bytes();
        let alg = ECDSA_P384_SHA384;
        assert!(alg.verify_signature(&public, b"message", &der[..n]).is_ok());
        assert!(
            alg.verify_signature(&public, b"messagf", &der[..n])
                .is_err()
        );
        assert!(
            ECDSA_P384_SHA256
                .verify_signature(&public, b"message", &der[..n])
                .is_err()
        );
        let mut compressed = [0u8; 49];
        compressed[0] = 0x02 | (public[96] & 1);
        compressed[1..].copy_from_slice(&public[1..49]);
        assert!(
            alg.verify_signature(&compressed, b"message", &der[..n])
                .is_err()
        );
        // The fixed form is not what TLS carries.
        assert!(alg.verify_signature(&public, b"message", &sig).is_err());
    }

    /// A 1024-bit key's genuine signature is refused for its size.
    #[test]
    fn small_rsa_keys_are_refused() {
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = rsa::PrivateKey::generate(&mut rng, 1024).unwrap();
        let sig = key.sign_pkcs1::<Sha256>(b"message").unwrap();
        let mut public = [0u8; 300];
        let n = key.public_key().pkcs1_bytes(&mut public).unwrap();
        assert!(
            RSA_PKCS1_2048_8192_SHA256
                .verify_signature(&public[..n], b"message", sig.as_ref())
                .is_err()
        );
        assert!(
            key.public_key()
                .verify_pkcs1::<Sha256>(b"message", sig.as_ref())
                .is_ok()
        );
    }

    /// Every algorithm the handshake mapping names is one a chain may
    /// use too, and the mapping offers the schemes in the documented
    /// order.
    #[test]
    fn mapping_is_consistent() {
        let schemes = SUPPORTED_SIG_ALGS.supported_schemes();
        assert_eq!(schemes[0], SignatureScheme::ECDSA_NISTP384_SHA384);
        assert_eq!(schemes[3], SignatureScheme::ED25519);
        assert_eq!(schemes.len(), 10);
        for alg in SUPPORTED_SIG_ALGS.mapping().iter().flat_map(|m| m.1.iter())
        {
            assert!(
                ALL_VERIFICATION_ALGS
                    .iter()
                    .any(|a| core::ptr::addr_eq(*a, *alg)),
                "{alg:?}"
            );
        }
    }
}
