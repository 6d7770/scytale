//! Signatures: Ed25519, ECDSA over P-256 and P-384, and RSA.
//!
//! Verification goes through [`UnparsedPublicKey`] and a `static`
//! naming the algorithm. Signing goes through a key pair type per
//! algorithm.

use core::fmt;

use scytale::Key;
use scytale::hash::sha2::{Sha256, Sha384};
use scytale::sig::ecdsa::{p256, p384};
use scytale::sig::ed25519;
use zeroize::Zeroize;

use crate::debug::HexStr;
use crate::error::{self, KeyRejected};
use crate::{pkcs8, pkcs8_peek, rand, sealed};

pub use crate::rsa::{
    PublicKeyComponents as RsaPublicKeyComponents,
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
    RsaEncoding, RsaParameters,
};

/// A key pair that signs with RSA.
pub type RsaKeyPair = crate::rsa::KeyPair;

/// The longest signature a key pair here returns: an ASN.1 ECDSA
/// signature over P-384, both integers with a leading zero.
const MAX_LEN: usize = 1 + 2 + 2 * (1 + 1 + 1 + 48);

/// A signature a key pair made.
#[derive(Clone, Copy)]
pub struct Signature {
    value: [u8; MAX_LEN],
    len: usize,
}

impl Signature {
    fn new(bytes: &[u8]) -> Self {
        let mut value = [0u8; MAX_LEN];
        value[..bytes.len()].copy_from_slice(bytes);
        Signature {
            value,
            len: bytes.len(),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.len]
    }
}

/// A key pair, with the public half it hands out.
pub trait KeyPair: fmt::Debug + Send + Sized + Sync {
    /// The public key's type.
    type PublicKey: AsRef<[u8]> + fmt::Debug + Clone + Send + Sized + Sync;

    /// The public key.
    fn public_key(&self) -> &Self::PublicKey;
}

/// A signature algorithm that verifies. Sealed: the only values are the
/// `static`s here.
pub trait VerificationAlgorithm: fmt::Debug + Sync + sealed::Sealed {
    /// Checks `signature` over `msg` under `public_key`.
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified>;
}

/// A public key and the algorithm to verify with it, not yet checked.
#[derive(Clone, Copy)]
pub struct UnparsedPublicKey<B> {
    algorithm: &'static dyn VerificationAlgorithm,
    bytes: B,
}

impl<B> AsRef<[u8]> for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<B: fmt::Debug> fmt::Debug for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UnparsedPublicKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &HexStr(self.bytes.as_ref()))
            .finish()
    }
}

impl<B> UnparsedPublicKey<B> {
    /// A key for `algorithm`.
    #[inline]
    pub fn new(
        algorithm: &'static dyn VerificationAlgorithm,
        bytes: B,
    ) -> Self {
        Self { algorithm, bytes }
    }

    /// Checks `signature` over `message`.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), error::Unspecified>
    where
        B: AsRef<[u8]>,
    {
        self.algorithm.verify(
            untrusted::Input::from(self.bytes.as_ref()),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        )
    }
}

// Ed25519.

/// The length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = ed25519::PUBLIC_KEY_SIZE;

/// Ed25519 verification parameters.
pub struct EdDSAParameters;

impl fmt::Debug for EdDSAParameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // ring's own spelling, which its tests compare against.
        f.write_str("ring::signature::ED25519")
    }
}

/// Ed25519 (RFC 8032).
pub static ED25519: EdDSAParameters = EdDSAParameters;

impl sealed::Sealed for EdDSAParameters {}

impl VerificationAlgorithm for EdDSAParameters {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let public_key: &[u8; ED25519_PUBLIC_KEY_LEN] =
            public_key.as_slice_less_safe().try_into()?;
        let signature: &[u8; ed25519::SIGNATURE_SIZE] =
            signature.as_slice_less_safe().try_into()?;
        ed25519::PublicKey::new(public_key)
            .verify(msg.as_slice_less_safe(), signature)
            .map_err(error::erase)
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy)]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        crate::debug::write_hex_tuple(f, "PublicKey", &self.0)
    }
}

/// An Ed25519 key pair.
pub struct Ed25519KeyPair {
    private: ed25519::PrivateKey,
    public_key: Ed25519PublicKey,
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl Ed25519KeyPair {
    fn from_private(private: ed25519::PrivateKey) -> Self {
        let public_key = Ed25519PublicKey(private.public_key().bytes());
        Ed25519KeyPair {
            private,
            public_key,
        }
    }

    /// A fresh key pair from `rng`, as a PKCS#8 version 2 document
    /// carrying the public key, which [`from_pkcs8`](Self::from_pkcs8)
    /// reads back.
    pub fn generate_pkcs8(
        rng: &dyn rand::SecureRandom,
    ) -> Result<pkcs8::Document, error::Unspecified> {
        let mut seed = Key::from([0u8; ed25519::KEY_SIZE]);
        rng.fill(seed.as_mut())?;
        let mut der = ed25519::PrivateKey::new(&seed).der_bytes();
        let document = pkcs8::Document::new(&der);
        der.zeroize();
        Ok(document)
    }

    /// A key pair from PKCS#8 version 2 (RFC 5958's version 1), which
    /// must carry the public key; it is checked against the seed.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        pkcs8_peek::check(pkcs8, pkcs8_peek::ED25519)?;
        // ring refuses the version before it reads the key, so a
        // version 1 structure is refused for its version whatever
        // else is wrong with it.
        if pkcs8_peek::version(pkcs8) == Some(0) {
            return Err(KeyRejected::version_not_supported());
        }
        let mut fixed = [0u8; LEGACY_MAX];
        let pkcs8 = legacy_public_key_tag_fixed(pkcs8, &mut fixed);
        let (secret, form) = ed25519::secret_from_der_with_form(pkcs8)
            .map_err(KeyRejected::from_scytale)?;
        if !form.v1 {
            return Err(KeyRejected::version_not_supported());
        }
        if !form.public_key {
            return Err(KeyRejected::public_key_is_missing());
        }
        Ok(Self::from_seed(secret))
    }

    /// A key pair from PKCS#8 of either version. A version 2 structure
    /// must still carry the public key, which is checked against the
    /// seed; version 1 cannot carry one and is taken on the seed
    /// alone.
    pub fn from_pkcs8_maybe_unchecked(
        pkcs8: &[u8],
    ) -> Result<Self, KeyRejected> {
        pkcs8_peek::check(pkcs8, pkcs8_peek::ED25519)?;
        let mut fixed = [0u8; LEGACY_MAX];
        let pkcs8 = legacy_public_key_tag_fixed(pkcs8, &mut fixed);
        let (secret, form) = ed25519::secret_from_der_with_form(pkcs8)
            .map_err(KeyRejected::from_scytale)?;
        if form.v1 && !form.public_key {
            return Err(KeyRejected::public_key_is_missing());
        }
        Ok(Self::from_seed(secret))
    }

    fn from_seed(mut secret: [u8; ed25519::KEY_SIZE]) -> Self {
        let key = Key::from(secret);
        secret.zeroize();
        Self::from_private(ed25519::PrivateKey::new(&key))
    }

    /// A key pair from its 32-byte seed.
    pub fn from_seed_unchecked(seed: &[u8]) -> Result<Self, KeyRejected> {
        let seed = Key::<[u8; ed25519::KEY_SIZE]>::try_from(seed)
            .map_err(|_| KeyRejected::invalid_encoding())?;
        Ok(Self::from_private(ed25519::PrivateKey::new(&seed)))
    }

    /// A key pair from its seed, checked against the public key the
    /// caller holds for it.
    pub fn from_seed_and_public_key(
        seed: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        let pair = Self::from_seed_unchecked(seed)?;
        let public_key: &[u8; ED25519_PUBLIC_KEY_LEN] =
            public_key
                .try_into()
                .map_err(|_| KeyRejected::invalid_encoding())?;
        if pair.public_key.0 != *public_key {
            return Err(KeyRejected::inconsistent_components());
        }
        Ok(pair)
    }

    /// Signs `msg`.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        // ring's Ed25519 takes no generator, and ring's own tests check
        // RFC 8032's exact bytes, so this is the deterministic form.
        Signature::new(&self.private.sign_deterministic(msg))
    }
}

/// The longest structure the legacy repair handles: an RFC 5958
/// PrivateKeyInfo with attributes has no bound, but the ones ring
/// wrote are well under this.
const LEGACY_MAX: usize = 256;

/// `pkcs8` with the public key's tag repaired, if it carries the one
/// ring's early versions wrote.
///
/// RFC 5958 puts the public key in `[1] IMPLICIT BIT STRING`, one
/// primitive element, and that is what scytale reads. ring 0.16 wrote
/// `[1] EXPLICIT`, a constructed element around a whole BIT STRING,
/// and ring still reads its own old keys. scytale is right to refuse
/// them; a caller switching from ring may still hold one, so this
/// rewrites that one element, at the end of the structure where the
/// standard puts it, into the standard form: `A1 23 03 21 00 <key>`
/// becomes `81 21 00 <key>`, two bytes shorter, and the outer
/// length shrinks to match. Anything else is returned as it came.
fn legacy_public_key_tag_fixed<'a>(
    pkcs8: &'a [u8],
    fixed: &'a mut [u8; LEGACY_MAX],
) -> &'a [u8] {
    const KEY: usize = ED25519_PUBLIC_KEY_LEN;
    const LEGACY_TAIL: usize = 5 + KEY;
    let n = pkcs8.len();
    let legacy = (4 + LEGACY_TAIL..=LEGACY_MAX).contains(&n)
        && pkcs8[n - LEGACY_TAIL..n - KEY] == [0xa1, 0x23, 0x03, 0x21, 0x00];
    if !legacy {
        return pkcs8;
    }
    // Only the outer SEQUENCE's length changes. It is either one
    // byte, or the two-byte form 0x81 0xnn; the structure is too
    // small for any other.
    let (header, body) = match pkcs8 {
        [0x30, len, ..] if *len < 0x80 && usize::from(*len) + 2 == n => {
            (2, usize::from(*len))
        }
        [0x30, 0x81, len, ..] if usize::from(*len) + 3 == n => {
            (3, usize::from(*len))
        }
        _ => return pkcs8,
    };
    let out = &mut fixed[..n - 2];
    out[..n - LEGACY_TAIL].copy_from_slice(&pkcs8[..n - LEGACY_TAIL]);
    let tail = n - LEGACY_TAIL;
    out[tail] = 0x81;
    out[tail + 1] = 0x21;
    out[tail + 2] = 0x00;
    out[tail + 3..].copy_from_slice(&pkcs8[n - KEY..]);
    // The new length may fit one byte where the old took two.
    let len = body - 2;
    if header == 3 && len < 0x80 {
        out.copy_within(2.., 1);
        out[1] = len as u8;
        &out[..n - 3]
    } else {
        out[header - 1] = len as u8;
        out
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

// ECDSA.

#[derive(Clone, Copy, Eq, PartialEq)]
enum Curve {
    P256,
    P384,
}

#[derive(Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
}

/// Which ECDSA verification a `static` is, and what [`Debug`] prints.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
enum VerifyId {
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_FIXED,
}

/// ECDSA verification over a curve, a hash and a signature format.
pub struct EcdsaVerificationAlgorithm {
    id: VerifyId,
    curve: Curve,
    hash: Hash,
    asn1: bool,
}

impl fmt::Debug for EcdsaVerificationAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.id, f)
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}

/// An uncompressed point of exactly the curve's length. scytale also
/// takes compressed points; ring does not.
fn uncompressed(bytes: &[u8], len: usize) -> Result<&[u8], error::Unspecified> {
    match bytes.first() {
        Some(0x04) if bytes.len() == len => Ok(bytes),
        _ => Err(error::Unspecified),
    }
}

impl VerificationAlgorithm for EcdsaVerificationAlgorithm {
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let public_key = public_key.as_slice_less_safe();
        let msg = msg.as_slice_less_safe();
        let signature = signature.as_slice_less_safe();
        macro_rules! verify {
            ($curve:ident) => {{
                let point = uncompressed(public_key, $curve::PUBLIC_KEY_SIZE)?;
                let key = $curve::PublicKey::try_from_sec1(point)
                    .map_err(error::erase)?;
                let sig = if self.asn1 {
                    $curve::signature_from_der(signature)
                        .map_err(error::erase)?
                } else {
                    *<&[u8; $curve::SIGNATURE_SIZE]>::try_from(signature)?
                };
                match self.hash {
                    Hash::Sha256 => key.verify::<Sha256>(msg, &sig),
                    Hash::Sha384 => key.verify::<Sha384>(msg, &sig),
                }
                .map_err(error::erase)
            }};
        }
        match self.curve {
            Curve::P256 => verify!(p256),
            Curve::P384 => verify!(p384),
        }
    }
}

macro_rules! ecdsa_verify {
    ($name:ident, $curve:ident, $hash:ident, $asn1:expr, $doc:literal) => {
        #[doc = $doc]
        pub static $name: EcdsaVerificationAlgorithm =
            EcdsaVerificationAlgorithm {
                id: VerifyId::$name,
                curve: Curve::$curve,
                hash: Hash::$hash,
                asn1: $asn1,
            };
    };
}

ecdsa_verify!(
    ECDSA_P256_SHA256_ASN1,
    P256,
    Sha256,
    true,
    "ECDSA over P-256 with SHA-256, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P256_SHA256_FIXED,
    P256,
    Sha256,
    false,
    "ECDSA over P-256 with SHA-256, signatures as `r || s`."
);
ecdsa_verify!(
    ECDSA_P256_SHA384_ASN1,
    P256,
    Sha384,
    true,
    "ECDSA over P-256 with SHA-384, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P384_SHA256_ASN1,
    P384,
    Sha256,
    true,
    "ECDSA over P-384 with SHA-256, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P384_SHA384_ASN1,
    P384,
    Sha384,
    true,
    "ECDSA over P-384 with SHA-384, signatures in ASN.1 DER."
);
ecdsa_verify!(
    ECDSA_P384_SHA384_FIXED,
    P384,
    Sha384,
    false,
    "ECDSA over P-384 with SHA-384, signatures as `r || s`."
);

/// Which ECDSA signing a `static` is, and what [`Debug`] prints.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignId {
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
}

/// ECDSA signing over a curve, its hash and a signature format.
pub struct EcdsaSigningAlgorithm {
    id: SignId,
    curve: Curve,
    asn1: bool,
}

impl fmt::Debug for EcdsaSigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.id, f)
    }
}

impl PartialEq for EcdsaSigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for EcdsaSigningAlgorithm {}

impl sealed::Sealed for EcdsaSigningAlgorithm {}

macro_rules! ecdsa_sign {
    ($name:ident, $curve:ident, $asn1:expr, $doc:literal) => {
        #[doc = $doc]
        pub static $name: EcdsaSigningAlgorithm = EcdsaSigningAlgorithm {
            id: SignId::$name,
            curve: Curve::$curve,
            asn1: $asn1,
        };
    };
}

ecdsa_sign!(
    ECDSA_P256_SHA256_FIXED_SIGNING,
    P256,
    false,
    "ECDSA over P-256 with SHA-256, signing `r || s`."
);
ecdsa_sign!(
    ECDSA_P384_SHA384_FIXED_SIGNING,
    P384,
    false,
    "ECDSA over P-384 with SHA-384, signing `r || s`."
);
ecdsa_sign!(
    ECDSA_P256_SHA256_ASN1_SIGNING,
    P256,
    true,
    "ECDSA over P-256 with SHA-256, signing ASN.1 DER."
);
ecdsa_sign!(
    ECDSA_P384_SHA384_ASN1_SIGNING,
    P384,
    true,
    "ECDSA over P-384 with SHA-384, signing ASN.1 DER."
);

/// The longest ECDSA public key: an uncompressed P-384 point.
const EC_PUBLIC_KEY_MAX: usize = p384::PUBLIC_KEY_SIZE;

/// An ECDSA public key, as an uncompressed point.
#[derive(Clone, Copy)]
pub struct EcdsaPublicKey {
    bytes: [u8; EC_PUBLIC_KEY_MAX],
    len: usize,
}

impl EcdsaPublicKey {
    fn new(point: &[u8]) -> Self {
        let mut bytes = [0u8; EC_PUBLIC_KEY_MAX];
        bytes[..point.len()].copy_from_slice(point);
        EcdsaPublicKey {
            bytes,
            len: point.len(),
        }
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        crate::debug::write_hex_tuple(f, "PublicKey", self.as_ref())
    }
}

enum EcdsaPrivate {
    P256(p256::PrivateKey),
    P384(p384::PrivateKey),
}

/// An ECDSA key pair.
///
/// Its signatures are deterministic (RFC 6979). ring's are randomised;
/// both verify the same, but the bytes differ.
pub struct EcdsaKeyPair {
    private: EcdsaPrivate,
    public_key: EcdsaPublicKey,
    alg: &'static EcdsaSigningAlgorithm,
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl EcdsaKeyPair {
    fn from_private(
        alg: &'static EcdsaSigningAlgorithm,
        private: EcdsaPrivate,
    ) -> Self {
        let public_key = match &private {
            EcdsaPrivate::P256(k) => {
                EcdsaPublicKey::new(&k.public_key().sec1_bytes())
            }
            EcdsaPrivate::P384(k) => {
                EcdsaPublicKey::new(&k.public_key().sec1_bytes())
            }
        };
        EcdsaKeyPair {
            private,
            public_key,
            alg,
        }
    }

    /// A fresh key pair from `rng`, as a PKCS#8 document carrying the
    /// public point, which [`from_pkcs8`](Self::from_pkcs8) reads back.
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<pkcs8::Document, error::Unspecified> {
        macro_rules! generate {
            ($curve:ident) => {{
                let key =
                    crate::agreement::draw(rng, $curve::PrivateKey::try_new)?;
                let mut der = [0u8; $curve::DER_SIZE];
                let n = key.der_bytes(&mut der).map_err(error::erase)?;
                let document = pkcs8::Document::new(&der[..n]);
                der.zeroize();
                Ok(document)
            }};
        }
        match alg.curve {
            Curve::P256 => generate!(p256),
            Curve::P384 => generate!(p384),
        }
    }

    /// A key pair from PKCS#8 on the algorithm's curve. A public key
    /// carried in it is checked against the private one.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
        _rng: &dyn rand::SecureRandom,
    ) -> Result<Self, KeyRejected> {
        let expected = match alg.curve {
            Curve::P256 => pkcs8_peek::EC_P256,
            Curve::P384 => pkcs8_peek::EC_P384,
        };
        pkcs8_peek::check(pkcs8, expected)?;
        let (private, form) = match alg.curve {
            Curve::P256 => p256::PrivateKey::try_from_der_with_form(pkcs8)
                .map(|(k, f)| (EcdsaPrivate::P256(k), f)),
            Curve::P384 => p384::PrivateKey::try_from_der_with_form(pkcs8)
                .map(|(k, f)| (EcdsaPrivate::P384(k), f)),
        }
        .map_err(KeyRejected::from_scytale)?;
        // RFC 5915 makes the public point optional; ring requires it,
        // and calls its absence an encoding error.
        if !form.public_key {
            return Err(KeyRejected::invalid_encoding());
        }
        Ok(Self::from_private(alg, private))
    }

    /// A key pair from the private scalar, big-endian, and the public
    /// key as an uncompressed point, which must agree.
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
        _rng: &dyn rand::SecureRandom,
    ) -> Result<Self, KeyRejected> {
        macro_rules! load {
            ($curve:ident, $arm:ident) => {{
                let scalar: &[u8; $curve::KEY_SIZE] = private_key
                    .try_into()
                    .map_err(|_| KeyRejected::invalid_encoding())?;
                $curve::PrivateKey::try_new(scalar)
                    .map(EcdsaPrivate::$arm)
                    .map_err(|_| KeyRejected::invalid_component())?
            }};
        }
        let private = match alg.curve {
            Curve::P256 => load!(p256, P256),
            Curve::P384 => load!(p384, P384),
        };
        let pair = Self::from_private(alg, private);
        if pair.public_key.as_ref() != public_key {
            return Err(KeyRejected::inconsistent_components());
        }
        Ok(pair)
    }

    /// Signs `message`. `rng` is accepted for ring's signature and not
    /// used: the nonce comes from the key and the message.
    pub fn sign(
        &self,
        _rng: &dyn rand::SecureRandom,
        message: &[u8],
    ) -> Result<Signature, error::Unspecified> {
        macro_rules! sign {
            ($curve:ident, $key:expr, $hash:ty) => {{
                let fixed = $key
                    .sign_deterministic::<$hash>(message)
                    .map_err(error::erase)?;
                if self.alg.asn1 {
                    let mut der = [0u8; MAX_LEN];
                    let len = $curve::signature_der(&fixed, &mut der)
                        .map_err(error::erase)?;
                    Ok(Signature::new(&der[..len]))
                } else {
                    Ok(Signature::new(&fixed))
                }
            }};
        }
        match &self.private {
            EcdsaPrivate::P256(k) => sign!(p256, k, Sha256),
            EcdsaPrivate::P384(k) => sign!(p384, k, Sha384),
        }
    }
}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = EcdsaPublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests;
