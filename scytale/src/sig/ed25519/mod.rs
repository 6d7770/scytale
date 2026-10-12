//! Ed25519 (RFC 8032): signatures over the edwards25519 curve.
//!
//! The signer's secret is 32 bytes; SHA-512 expands it into a scalar
//! and a prefix. A signature commits to the message twice over: `R`
//! is a point derived from the prefix and the message, and `s` binds
//! the secret scalar to a hash of `R`, the public key and the
//! message. Verification checks the one equation `sB = R + kA`.
//!
//! RFC 8032 makes signing deterministic: the nonce is a hash of a
//! secret prefix and the message, so a weak generator cannot leak
//! the key the way it can with ECDSA. But two signatures of one
//! message are then the same computation, and a fault injected into
//! one, or a power trace of the hashing, can recover the key.
//! [`sign`] and its kin hedge the nonce against that, as
//! draft-irtf-cfrg-det-sigs-with-noise-05 section 3 says: 32 random
//! bytes are hashed into the prefix first, so no two signatures
//! share the computation, and a weak random source leaves the nonce
//! as good as RFC 8032's. Verifiers cannot tell the difference.
//! [`sign_deterministic`] and its kin are RFC 8032 exactly, for test
//! vectors and the protocols that need the same signature twice.
//!
//! All three variants of RFC 8032 section 5.1 are here. Plain
//! Ed25519, [`sign`] and [`verify`], is the one to reach for.
//! Ed25519ctx, [`sign_ctx`], adds a context string that separates a
//! key's signatures across uses, for a protocol that assigns one.
//! Ed25519ph, [`sign_ph`], signs a SHA-512 digest the caller has
//! already made, so a message too large to hold can be hashed as it
//! arrives, and takes a context too. The three never accept each
//! other's signatures.
//!
//! Keys are 32 bytes each way. [`PrivateKey`] and [`PublicKey`] are
//! the pair to reach for: the secret is held in a [`Key`], so it is
//! wiped when it goes out of scope, and each carries the RFC 8410
//! encodings the rest of the world stores keys in. The free functions
//! below take the bare bytes, for code that already has them.
//!
//! ```
//! use scytale::Key;
//! use scytale::random::CtrDrbg;
//! use scytale::sig::ed25519::PrivateKey;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::new(&Key::from([0x42u8; 32]));
//! let signature = key.sign(&mut rng, b"the message")?;
//! key.public_key().verify(b"the message", &signature)?;
//! assert!(key.public_key().verify(b"another", &signature).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! Signing performs the same sequence of field and scalar operations
//! whatever the secret. Multiplying the base point reads a table of
//! its multiples, and the read scans every entry, choosing by a mask,
//! so the secret digit that selects one never becomes an index or a
//! branch. Verification handles only public data, so it takes the
//! faster path whose work depends on the scalars: one pass over both
//! in signed digits, adding only where a digit is nonzero.
//!
//! # What verification accepts
//!
//! The checks are the ones RFC 8032 requires: the public key and `R`
//! must decode (a coordinate at or above the field prime does not),
//! and `s` must be below the group order, which is what stops an
//! accepted signature from being malleated into a second accepted
//! one. The equation is checked without the cofactor, matching the
//! bulk of deployed verifiers.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::der;
use crate::hash::Hash;
use crate::hash::sha2::Sha512;
use crate::math::fe25519::Fe;
use crate::{Error, Key, Pkcs8Form, Random};

mod base;

/// The length of a secret key.
pub const KEY_SIZE: usize = 32;

/// The length of a public key.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// The length of a signature.
pub const SIGNATURE_SIZE: usize = 64;

/// The public key belonging to `secret`.
///
/// Any 32 bytes are a valid secret key; take them from
/// [`random`](crate::random).
pub fn public_key(secret: &[u8; KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    let mut h = Sha512::digest(secret);
    let mut a = secret_scalar(&h);
    let public = Point::mul_base(&a).compress();
    h.zeroize();
    a.zeroize();
    public
}

/// The 32 random bytes that hedge one signature's nonce.
fn noise<R: Random>(rng: &mut R) -> Result<[u8; 32], Error> {
    let mut z = [0u8; 32];
    rng.fill(&mut z)?;
    Ok(z)
}

/// Signs `message` with `secret`, the nonce hedged by 32 bytes from
/// `rng`: see the module's notes.
pub fn sign<R: Random>(
    secret: &[u8; KEY_SIZE],
    rng: &mut R,
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let mut z = noise(rng)?;
    let signature =
        sign_with(secret, &public_key(secret), &[], message, Some(&z));
    z.zeroize();
    Ok(signature)
}

/// Signs `message` with `secret` as RFC 8032 does, the same key and
/// message always giving the same signature. For test vectors and
/// repeatable output; [`sign`] otherwise.
pub fn sign_deterministic(
    secret: &[u8; KEY_SIZE],
    message: &[u8],
) -> [u8; SIGNATURE_SIZE] {
    sign_with(secret, &public_key(secret), &[], message, None)
}

/// Checks that `signature` signs `message` under `public`.
///
/// [`Error::InvalidPublicKey`] when the key does not name a point on
/// the curve; [`Error::InvalidSignature`] for everything else, which
/// deliberately says no more than that.
pub fn verify(
    public: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    verify_with(public, &[], message, signature)
}

/// The longest context string Ed25519ctx and Ed25519ph take.
pub const CONTEXT_MAX: usize = 255;

/// The length of the SHA-512 digest Ed25519ph signs.
pub const PREHASH_SIZE: usize = 64;

/// Signs `message` under `context` with `secret`, by Ed25519ctx, the
/// nonce hedged by 32 bytes from `rng`.
///
/// The context is 1 to [`CONTEXT_MAX`] bytes; anything else is
/// [`Error::InvalidLength`]. RFC 8032 says it should not be empty,
/// and a use with no context to give is plain [`sign`]'s.
pub fn sign_ctx<R: Random>(
    secret: &[u8; KEY_SIZE],
    rng: &mut R,
    context: &[u8],
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom2(CTX, context)?;
    let mut z = noise(rng)?;
    let signature = sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        message,
        Some(&z),
    );
    z.zeroize();
    Ok(signature)
}

/// Ed25519ctx as RFC 8032 does it, deterministically; the context
/// is refused as [`sign_ctx`] refuses it.
pub fn sign_ctx_deterministic(
    secret: &[u8; KEY_SIZE],
    context: &[u8],
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom2(CTX, context)?;
    Ok(sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        message,
        None,
    ))
}

/// Checks that `signature` signs `message` under `context` and
/// `public`, by Ed25519ctx. The context is refused as [`sign_ctx`]
/// refuses it, and the errors are otherwise [`verify`]'s.
pub fn verify_ctx(
    public: &[u8; PUBLIC_KEY_SIZE],
    context: &[u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    let head = dom2(CTX, context)?;
    verify_with(public, &[&head, context], message, signature)
}

/// Signs the SHA-512 digest `prehash` under `context` with `secret`,
/// by Ed25519ph, the nonce hedged by 32 bytes from `rng`.
///
/// The digest is what the caller has hashed the message to, in as
/// many pieces as it arrived in, which is the reason to choose this
/// variant. The context is up to [`CONTEXT_MAX`] bytes and may be
/// empty; a longer one is [`Error::InvalidLength`].
///
/// ```
/// use scytale::hash::Hash;
/// use scytale::hash::sha2::Sha512;
/// use scytale::random::CtrDrbg;
/// use scytale::sig::ed25519;
///
/// # fn main() -> Result<(), scytale::Error> {
/// let mut rng = CtrDrbg::from_system()?;
/// let secret = [0x42u8; 32];
/// let mut hasher = Sha512::new();
/// hasher.update(b"a message that ");
/// hasher.update(b"arrives in parts");
/// let prehash = hasher.finalize();
/// let signature = ed25519::sign_ph(&secret, &mut rng, b"", &prehash)?;
/// let public = ed25519::public_key(&secret);
/// ed25519::verify_ph(&public, b"", &prehash, &signature)?;
/// # Ok(())
/// # }
/// ```
pub fn sign_ph<R: Random>(
    secret: &[u8; KEY_SIZE],
    rng: &mut R,
    context: &[u8],
    prehash: &[u8; PREHASH_SIZE],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom2(PH, context)?;
    let mut z = noise(rng)?;
    let signature = sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        prehash,
        Some(&z),
    );
    z.zeroize();
    Ok(signature)
}

/// Ed25519ph as RFC 8032 does it, deterministically; the context is
/// refused as [`sign_ph`] refuses it.
pub fn sign_ph_deterministic(
    secret: &[u8; KEY_SIZE],
    context: &[u8],
    prehash: &[u8; PREHASH_SIZE],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let head = dom2(PH, context)?;
    Ok(sign_with(
        secret,
        &public_key(secret),
        &[&head, context],
        prehash,
        None,
    ))
}

/// Checks that `signature` signs the SHA-512 digest `prehash` under
/// `context` and `public`, by Ed25519ph. The context is refused as
/// [`sign_ph`] refuses it, and the errors are otherwise [`verify`]'s.
pub fn verify_ph(
    public: &[u8; PUBLIC_KEY_SIZE],
    context: &[u8],
    prehash: &[u8; PREHASH_SIZE],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    let head = dom2(PH, context)?;
    verify_with(public, &[&head, context], prehash, signature)
}

/// The phflag of Ed25519ctx.
const CTX: u8 = 0;

/// The phflag of Ed25519ph.
const PH: u8 = 1;

/// The fixed part of RFC 8032's `dom2(phflag, context)`: the name,
/// the flag and the context's length. The context follows it into
/// both hashes, which is what keeps a signature under one variant or
/// context from verifying under another. Ed25519ctx takes a context
/// of at least a byte, Ed25519ph any up to [`CONTEXT_MAX`].
fn dom2(flag: u8, context: &[u8]) -> Result<[u8; 34], Error> {
    let shortest = if flag == CTX { 1 } else { 0 };
    if context.len() < shortest || context.len() > CONTEXT_MAX {
        return Err(Error::InvalidLength(context.len()));
    }
    let mut head = [0u8; 34];
    head[..32].copy_from_slice(b"SigEd25519 no Ed25519 collisions");
    head[32] = flag;
    head[33] = context.len() as u8;
    Ok(head)
}

/// Signs `message` with `secret`, whose public key `public` must be,
/// with `dom` hashed ahead of both hashes: nothing for Ed25519, and
/// `dom2` and the context for the other two. A [`PrivateKey`] has
/// derived the public key already, and deriving it again would cost
/// as much as the signature's own multiplication. With `noise`, the
/// nonce is hedged as the module's notes say.
fn sign_with(
    secret: &[u8; KEY_SIZE],
    public: &[u8; PUBLIC_KEY_SIZE],
    dom: &[&[u8]],
    message: &[u8],
    noise: Option<&[u8; 32]>,
) -> [u8; SIGNATURE_SIZE] {
    let mut h = Sha512::digest(secret);
    let mut a = secret_scalar(&h);

    // The prefix, or hedged, the first half of SHA-512(prefix || Z):
    // the secret meets the random bytes before anything public.
    let mut prefix = [0u8; 32];
    match noise {
        Some(z) => {
            let mut hasher = Sha512::new();
            hasher.update(&h[32..]);
            hasher.update(z);
            let mut mixed = hasher.finalize();
            prefix.copy_from_slice(&mixed[..32]);
            mixed.zeroize();
        }
        None => prefix.copy_from_slice(&h[32..]),
    }

    // The nonce: a hash of the prefix and the message, so it is
    // unique per message whatever the random source does.
    let mut hasher = Sha512::new();
    for part in dom {
        hasher.update(part);
    }
    hasher.update(&prefix);
    prefix.zeroize();
    hasher.update(message);
    let mut wide = hasher.finalize();
    let mut r = Scalar::from_bytes_wide(&wide);
    let big_r = Point::mul_base(&r).compress();

    // The challenge binds R, the public key and the message.
    let k = challenge(dom, &big_r, public, message);

    let s = k.mulmod(&a).addmod(&r);
    let mut signature = [0u8; SIGNATURE_SIZE];
    signature[..32].copy_from_slice(&big_r);
    signature[32..].copy_from_slice(&s.to_bytes());

    h.zeroize();
    a.zeroize();
    wide.zeroize();
    r.zeroize();
    signature
}

/// Verification under any of the three variants, `dom` as
/// [`sign_with`] takes it.
fn verify_with(
    public: &[u8; PUBLIC_KEY_SIZE],
    dom: &[&[u8]],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), Error> {
    let a = Point::decompress(public).ok_or(Error::InvalidPublicKey)?;

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    // s at or above the group order is the malleable form of another
    // signature, and RFC 8032 says to refuse it.
    if !Scalar::is_below_order(&s_bytes) {
        return Err(Error::InvalidSignature);
    }
    let s = Scalar::from_bytes_reduced(&s_bytes);

    let mut big_r = [0u8; 32];
    big_r.copy_from_slice(&signature[..32]);
    let k = challenge(dom, &big_r, public, message);

    // sB = R + kA, checked as R = sB - kA so R need never be
    // decompressed: its bytes are compared directly.
    if a.neg().mul_add_base_vartime(&k, &s).compress() == big_r {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// `k = H(dom || R || A || M)`, reduced into the group.
fn challenge(
    dom: &[&[u8]],
    big_r: &[u8; 32],
    public: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    for part in dom {
        hasher.update(part);
    }
    hasher.update(big_r);
    hasher.update(public);
    hasher.update(message);
    Scalar::from_bytes_wide(&hasher.finalize())
}

/// The length of a secret key's DER encoding, a PKCS#8
/// `PrivateKeyInfo` (RFC 8410 section 7).
pub const DER_SIZE: usize = 48;

/// The length of a public key's DER encoding, a
/// `SubjectPublicKeyInfo` (RFC 8410 section 4).
pub const PUBLIC_KEY_DER_SIZE: usize = 44;

/// The length of a secret key's PEM encoding, a `PRIVATE KEY` block.
pub const PEM_SIZE: usize = 119;

/// The length of a public key's PEM encoding, a `PUBLIC KEY` block.
pub const PUBLIC_KEY_PEM_SIZE: usize = 113;

/// A secret key from its DER PKCS#8 `PrivateKeyInfo`, the form under
/// `PRIVATE KEY` in a PEM file, which RFC 8410 fixes for Ed25519: the
/// 32 bytes in an OCTET STRING of their own inside the one PKCS#8
/// provides. A version 1 structure that also carries the public key
/// is read, and refused as [`Error::InconsistentKey`] when that key
/// is not the secret's. A structure under another identifier, the
/// other curve's included, or under `id-Ed25519` with the NULL
/// parameters RFC 8410 forbids, is [`Error::WrongAlgorithm`];
/// anything else wrong with the bytes is [`Error::InvalidEncoding`].
pub fn secret_from_der(der: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    secret_from_der_with_form(der).map(|(secret, _)| secret)
}

/// As [`secret_from_der`], and also which form the structure took.
pub fn secret_from_der_with_form(
    der: &[u8],
) -> Result<([u8; KEY_SIZE], Pkcs8Form), Error> {
    let found = der::curve_secret_from_der(&der::ED25519, der)?;
    let form = Pkcs8Form {
        v1: found.v1,
        public_key: found.public.is_some(),
    };
    Ok((checked(found.secret, found.public)?, form))
}

/// The secret a structure carried, once the public key it may
/// have carried beside it is checked to be the secret's own: a pair
/// that disagrees has been corrupted, and neither half is returned.
fn checked(
    mut secret: [u8; KEY_SIZE],
    carried: Option<[u8; PUBLIC_KEY_SIZE]>,
) -> Result<[u8; KEY_SIZE], Error> {
    if let Some(carried) = carried {
        let derived = public_key(&secret);
        if derived != carried {
            secret.zeroize();
            return Err(Error::InconsistentKey);
        }
    }
    Ok(secret)
}

/// The secret key's DER encoding, a version 0 `PrivateKeyInfo`. The
/// output is a secret, to be wiped when done.
pub fn secret_der(secret: &[u8; KEY_SIZE]) -> [u8; DER_SIZE] {
    der::curve_secret_der(&der::ED25519, secret)
}

/// A public key from its DER `SubjectPublicKeyInfo`, the form under
/// `PUBLIC KEY`. The bytes are not checked to be a point here, any
/// more than the argument type of the functions that take them
/// checks; those refuse one that is not.
pub fn public_key_from_der(der: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], Error> {
    der::curve_public_from_der(&der::ED25519, der)
}

/// The public key's DER encoding.
pub fn public_key_der(
    public: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; PUBLIC_KEY_DER_SIZE] {
    der::curve_public_der(&der::ED25519, public)
}

/// A secret key from a `PRIVATE KEY` PEM block (RFC 7468) around
/// [`secret_der`]'s bytes. Whitespace and line ends are read
/// leniently; anything else that is not exactly one well-formed
/// block, an encrypted key included, is [`Error::InvalidEncoding`].
pub fn secret_from_pem(pem: &[u8]) -> Result<[u8; KEY_SIZE], Error> {
    let found = der::curve_secret_from_pem(&der::ED25519, pem)?;
    let (secret, carried) = (found.secret, found.public);
    checked(secret, carried)
}

/// The secret key as a `PRIVATE KEY` PEM block: ASCII with LF line
/// ends, always [`PEM_SIZE`] bytes. A secret, to be wiped when done.
pub fn secret_pem(secret: &[u8; KEY_SIZE]) -> [u8; PEM_SIZE] {
    der::curve_secret_pem(&der::ED25519, secret)
}

/// A public key from a `PUBLIC KEY` PEM block, read as
/// [`secret_from_pem`] reads its block.
pub fn public_key_from_pem(pem: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], Error> {
    der::curve_public_from_pem(&der::ED25519, pem)
}

/// The public key as a `PUBLIC KEY` PEM block, always
/// [`PUBLIC_KEY_PEM_SIZE`] bytes.
pub fn public_key_pem(
    public: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; PUBLIC_KEY_PEM_SIZE] {
    der::curve_public_pem(&der::ED25519, public)
}

/// The length of a key pair's DER encoding, a version 1
/// `PrivateKeyInfo` carrying the public key beside the seed.
pub const PAIR_DER_SIZE: usize = der::CURVE_PAIR_DER;

/// The length of a key pair's PEM encoding, a `PRIVATE KEY` block.
pub const PAIR_PEM_SIZE: usize = der::CURVE_PAIR_PEM;

/// A signing key, and the public key that goes with it.
///
/// The secret is held in a [`Key`], so it is wiped when the key goes
/// out of scope; the free functions above take the bare bytes for
/// code that has them already.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    secret: Key<[u8; KEY_SIZE]>,
    #[zeroize(skip)]
    public: PublicKey,
}

/// A verifying key: a point in its compressed form.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl fmt::Debug for PrivateKey {
    /// Deliberately omits the secret; the public key is not one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey").finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// A key drawn from `rng`.
    ///
    /// Any 32 bytes are a secret key, so this is 32 bytes from the
    /// source and the public key they give.
    pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
        let mut secret = Key::zeroed();
        rng.fill(secret.as_mut())?;
        Ok(Self::new(&secret))
    }

    /// The key `secret` is the seed of.
    ///
    /// Every 32 bytes are a seed, so there is nothing to reject.
    pub fn new(secret: &Key<[u8; KEY_SIZE]>) -> Self {
        let public = PublicKey {
            bytes: public_key(secret.array()),
        };
        PrivateKey {
            secret: secret.clone(),
            public,
        }
    }

    /// The seed, to store or to hand to code that wants the bytes.
    pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
        *self.secret.array()
    }

    /// The public key, derived when this key was built.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Signs `message`, the nonce hedged by 32 bytes from `rng`, as
    /// [`sign`] does.
    pub fn sign<R: Random>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        self.hedged(rng, &[], message)
    }

    /// Signs `message` as RFC 8032 does, as [`sign_deterministic`]
    /// does.
    pub fn sign_deterministic(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        sign_with(self.secret.array(), &self.public.bytes, &[], message, None)
    }

    /// Signs `message` under `context`, by Ed25519ctx, hedged, as
    /// [`sign_ctx`] does.
    pub fn sign_ctx<R: Random>(
        &self,
        rng: &mut R,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom2(CTX, context)?;
        self.hedged(rng, &[&head, context], message)
    }

    /// Ed25519ctx deterministically, as [`sign_ctx_deterministic`]
    /// does.
    pub fn sign_ctx_deterministic(
        &self,
        context: &[u8],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom2(CTX, context)?;
        Ok(self.sign_dom(&[&head, context], message, None))
    }

    /// Signs the SHA-512 digest `prehash` under `context`, by
    /// Ed25519ph, hedged, as [`sign_ph`] does.
    pub fn sign_ph<R: Random>(
        &self,
        rng: &mut R,
        context: &[u8],
        prehash: &[u8; PREHASH_SIZE],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom2(PH, context)?;
        self.hedged(rng, &[&head, context], prehash)
    }

    /// Ed25519ph deterministically, as [`sign_ph_deterministic`]
    /// does.
    pub fn sign_ph_deterministic(
        &self,
        context: &[u8],
        prehash: &[u8; PREHASH_SIZE],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let head = dom2(PH, context)?;
        Ok(self.sign_dom(&[&head, context], prehash, None))
    }

    /// One signature under `dom`, hedged by bytes from `rng`.
    fn hedged<R: Random>(
        &self,
        rng: &mut R,
        dom: &[&[u8]],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE], Error> {
        let mut z = noise(rng)?;
        let signature = self.sign_dom(dom, message, Some(&z));
        z.zeroize();
        Ok(signature)
    }

    /// One signature under `dom`, hedged by `noise` if there is any.
    fn sign_dom(
        &self,
        dom: &[&[u8]],
        message: &[u8],
        noise: Option<&[u8; 32]>,
    ) -> [u8; SIGNATURE_SIZE] {
        sign_with(self.secret.array(), &self.public.bytes, dom, message, noise)
    }

    /// A key from its DER `PrivateKeyInfo`, of either version; a
    /// version 1 structure's public key is checked against the
    /// secret's own, as [`secret_from_der`] describes.
    pub fn try_from_der(bytes: &[u8]) -> Result<Self, Error> {
        let mut secret = Key::from(secret_from_der(bytes)?);
        let key = Self::new(&secret);
        secret.zeroize();
        Ok(key)
    }

    /// The key pair as a version 1 `PrivateKeyInfo`, which carries
    /// the public key beside the seed. The output is a secret, to be
    /// wiped when done.
    ///
    /// [`secret_der`] writes the version 0 form, which is what
    /// OpenSSL emits; this one is what readers that require the
    /// public key accept.
    pub fn der_bytes(&self) -> [u8; PAIR_DER_SIZE] {
        der::curve_pair_der(
            &der::ED25519,
            self.secret.array(),
            &self.public.bytes,
        )
    }

    /// A key from a `PRIVATE KEY` PEM block, read as
    /// [`secret_from_pem`] reads one.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        let mut secret = Key::from(secret_from_pem(pem)?);
        let key = Self::new(&secret);
        secret.zeroize();
        Ok(key)
    }

    /// The key pair as a `PRIVATE KEY` PEM block around
    /// [`der_bytes`](Self::der_bytes). A secret, to be wiped when
    /// done.
    pub fn pem_bytes(&self) -> [u8; PAIR_PEM_SIZE] {
        der::curve_pair_pem(
            &der::ED25519,
            self.secret.array(),
            &self.public.bytes,
        )
    }
}

impl PublicKey {
    /// The key those bytes are, unchecked: they are checked where
    /// they are used, as [`verify`] describes.
    pub fn new(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey { bytes: *bytes }
    }

    /// The compressed point.
    pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Checks that `signature` signs `message` under this key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<(), Error> {
        verify(&self.bytes, message, signature)
    }

    /// Checks that `signature` signs `message` under `context` and
    /// this key, by Ed25519ctx, as [`verify_ctx`] does.
    pub fn verify_ctx(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<(), Error> {
        verify_ctx(&self.bytes, context, message, signature)
    }

    /// Checks that `signature` signs the SHA-512 digest `prehash`
    /// under `context` and this key, by Ed25519ph, as [`verify_ph`]
    /// does.
    pub fn verify_ph(
        &self,
        context: &[u8],
        prehash: &[u8; PREHASH_SIZE],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<(), Error> {
        verify_ph(&self.bytes, context, prehash, signature)
    }

    /// A key from its DER `SubjectPublicKeyInfo`.
    pub fn try_from_der(bytes: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            bytes: public_key_from_der(bytes)?,
        })
    }

    /// The key's `SubjectPublicKeyInfo`.
    pub fn der_bytes(&self) -> [u8; PUBLIC_KEY_DER_SIZE] {
        public_key_der(&self.bytes)
    }

    /// A key from a `PUBLIC KEY` PEM block.
    pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey {
            bytes: public_key_from_pem(pem)?,
        })
    }

    /// The key as a `PUBLIC KEY` PEM block.
    pub fn pem_bytes(&self) -> [u8; PUBLIC_KEY_PEM_SIZE] {
        public_key_pem(&self.bytes)
    }
}

/// The u-coordinate of `k` times X25519's base point, with `k`
/// already clamped: the comb over the Ed25519 base table, then the
/// birational map `u = (1 + y) / (1 - y)` from the Edwards curve,
/// whose base point is the same point. A fixed-base comb and one
/// inversion cost much less than a ladder step for every bit, and
/// both are free of branches and lookups on the secret.
///
/// Reducing `k` modulo the group order changes nothing, since the
/// base point has that order; and a clamped `k` is a nonzero multiple
/// of nothing smaller, so the point is never the identity and `1 - y`
/// is never zero.
pub(crate) fn montgomery_base(k: &[u8; 32]) -> [u8; 32] {
    let mut scalar = Scalar::from_bytes_reduced(k);
    let mut point = Point::mul_base(&scalar);
    let u = point
        .z
        .add(&point.y)
        .mul(&point.z.sub(&point.y).invert())
        .to_bytes();
    scalar.0.zeroize();
    point.x.zeroize();
    point.y.zeroize();
    point.z.zeroize();
    point.t.zeroize();
    u
}

/// The secret scalar: the low half of the expanded secret, clamped
/// as RFC 8032 section 5.1.5 requires, reduced into the group.
///
/// Reduction changes nothing the curve can see: the base point's
/// order divides out.
fn secret_scalar(h: &[u8; 64]) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&h[..32]);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let scalar = Scalar::from_bytes_reduced(&bytes);
    bytes.zeroize();
    scalar
}

/// The curve constant d = -121665/121666.
const D: Fe = Fe([
    0x34dca135978a3,
    0x1a8283b156ebd,
    0x5e7a26001c029,
    0x739c663a03cbb,
    0x52036cee2b6ff,
]);

/// 2d, which the addition formula wants ready-made.
const D2: Fe = Fe([
    0x69b9426b2f159,
    0x35050762add7a,
    0x3cf44c0038052,
    0x6738cc7407977,
    0x2406d9dc56dff,
]);

/// A square root of -1, for correcting the root in decompression.
const SQRT_M1: Fe = Fe([
    0x61b274a0ea0b0,
    0x0d5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d,
]);

/// The blocks the comb cuts a scalar into.
const COMB: usize = 6;

/// The bits in a block: enough that six of them cover the 253 bits
/// of a reduced scalar.
const BLOCK: usize = 253usize.div_ceil(COMB);

/// An affine point as the mixed addition reads it: `y + x`, `y - x`
/// and `2dxy`, each fully reduced.
#[derive(Clone, Copy)]
struct Niels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

impl Niels {
    /// The neutral element, (0, 1).
    const IDENTITY: Niels = Niels {
        y_plus_x: Fe::ONE,
        y_minus_x: Fe::ONE,
        xy2d: Fe::ZERO,
    };

    /// Replaces `self` with `other` when `condition` is one, by a
    /// mask rather than a branch.
    fn cmov(&mut self, other: &Niels, condition: u64) {
        self.y_plus_x.cmov(&other.y_plus_x, condition);
        self.y_minus_x.cmov(&other.y_minus_x, condition);
        self.xy2d.cmov(&other.xy2d, condition);
    }

    /// `-P` is `(-x, y)`, which swaps the sum and the difference and
    /// negates the product.
    fn neg(&self) -> Niels {
        Niels {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            xy2d: self.xy2d.neg(),
        }
    }
}

/// The digit width for the public key's scalar in verification,
/// whose odd multiples are built per signature: eight of them.
const A_WIDTH: u32 = 5;

/// The digit width for the base point's scalar, whose odd multiples
/// are the 32 in [`base::ODD`].
const B_WIDTH: u32 = 7;

/// `scalar` in width-`width` non-adjacent form: digits that are zero
/// or odd, below `2^(width - 1)` in magnitude, with at least
/// `width - 1` zeros between any two nonzero ones, whose sum of
/// `digit[i] * 2^i` is the scalar. Branches on the scalar, so for
/// public ones only.
fn naf(scalar: &Scalar, width: u32) -> [i8; 256] {
    debug_assert!((2..=8).contains(&width));
    let mut words = [0u64; 5];
    words[..4].copy_from_slice(&scalar.0);
    let span = 1u64 << width;
    let mask = span - 1;

    let mut digits = [0i8; 256];
    let mut carry = 0u64;
    let mut pos = 0usize;
    while pos < 256 {
        let (word, bit) = (pos / 64, pos % 64);
        // The window can straddle a word; the fifth word is zero and
        // stands for the bits past the scalar.
        let mut window = words[word] >> bit;
        if bit > 0 {
            window |= words[word + 1] << (64 - bit);
        }
        let value = carry + (window & mask);
        // An even value has a zero bottom bit, carry included: no
        // digit here, and the carry moves up with the position.
        if value & 1 == 0 {
            pos += 1;
            continue;
        }
        // Past half the span the digit goes negative, and what it
        // borrowed from the next window is the carry.
        if value < span / 2 {
            carry = 0;
            digits[pos] = value as i8;
        } else {
            carry = 1;
            digits[pos] = (value as i64 - span as i64) as i8;
        }
        pos += width as usize;
    }
    // Reduced scalars are below 2^253, so nothing carries out.
    debug_assert_eq!(carry, 0);
    digits
}

/// A point in extended coordinates: x = X/Z, y = Y/Z, T = XY/Z.
///
/// The extra T coordinate is what lets one addition formula serve
/// every case, doubling included, with no exceptional inputs.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    /// The neutral element: (0, 1).
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// The unified addition of Hisil, Wong, Carter and Dawson,
    /// specialised to a = -1: correct for any pair of inputs,
    /// doubling included.
    fn add(&self, other: &Point) -> Point {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let zz = self.z.mul(&other.z);
        let d = zz.add(&zz);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Doubling, cheaper than adding a point to itself.
    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz.add(&zz);
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// `self + other`, where `other` is affine and precomputed: the
    /// general addition with `Z2 = 1` and the three products it
    /// would spend on `other` already made, so seven multiplications
    /// rather than nine. Complete, as that one is.
    fn add_niels(&self, other: &Niels) -> Point {
        let a = self.y.sub(&self.x).mul(&other.y_minus_x);
        let b = self.y.add(&self.x).mul(&other.y_plus_x);
        let c = self.t.mul(&other.xy2d);
        let d = self.z.add(&self.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// `scalar` times the base point, by the comb over the table in
    /// [`base`]: a doubling and one table addition for each bit of a
    /// block, rather than a doubling and an addition for each bit of
    /// the scalar. The table is public; only the digit that reads it
    /// is secret, so the read scans every entry and chooses by a
    /// mask.
    fn mul_base(scalar: &Scalar) -> Point {
        let mut bytes = scalar.to_bytes();
        let mut acc = Point::IDENTITY;
        for t in (0..BLOCK).rev() {
            acc = acc.double();
            // Bit `t` of every block, gathered least block first.
            // The last block runs past the 253 bits a reduced scalar
            // has, and those bits are zero.
            let mut digit = 0u64;
            for i in 0..COMB {
                let bit = i * BLOCK + t;
                if bit < 256 {
                    digit |= u64::from((bytes[bit >> 3] >> (bit & 7)) & 1) << i;
                }
            }
            // Entry `j` holds the digit `j + 1`, so a zero digit
            // matches nothing and leaves the identity, which is what
            // it stands for.
            let mut chosen = Niels::IDENTITY;
            for (j, entry) in base::BASE.iter().enumerate() {
                let index = j as u64 + 1;
                let matches = ((index ^ digit).wrapping_sub(1)) >> 63;
                chosen.cmov(entry, matches);
            }
            acc = acc.add_niels(&chosen);
        }
        // A copy of the scalar, which is the signing nonce on one
        // call and the key's own scalar on the other; the callers
        // wipe theirs, so this one goes too.
        bytes.zeroize();
        acc
    }

    /// `a` times `self` plus `b` times the base point, in one pass
    /// that shares the doublings: each scalar is written in signed
    /// odd digits, five bits wide for `self`, whose odd multiples are
    /// built here, and seven for the base point, whose are in
    /// [`base::ODD`]. A doubling for each bit and an addition for
    /// each nonzero digit, of which there are about one in six and
    /// one in eight.
    ///
    /// For public scalars only: which additions happen, and from
    /// which entries, is what the scalars are.
    fn mul_add_base_vartime(&self, a: &Scalar, b: &Scalar) -> Point {
        let a_digits = naf(a, A_WIDTH);
        let b_digits = naf(b, B_WIDTH);

        // self, 3 self, 5 self, ..., 15 self.
        let twice = self.double();
        let mut odd = [*self; 8];
        for i in 1..odd.len() {
            odd[i] = odd[i - 1].add(&twice);
        }

        let mut acc = Point::IDENTITY;
        let Some(top) = (0..256).rposition(|i| a_digits[i] | b_digits[i] != 0)
        else {
            return acc;
        };
        for i in (0..=top).rev() {
            acc = acc.double();
            // Digit `d` is odd, and `|d| / 2` indexes its multiple.
            let d = a_digits[i];
            let entry = usize::from(d.unsigned_abs() / 2);
            if d > 0 {
                acc = acc.add(&odd[entry]);
            } else if d < 0 {
                acc = acc.add(&odd[entry].neg());
            }
            let d = b_digits[i];
            let entry = usize::from(d.unsigned_abs() / 2);
            if d > 0 {
                acc = acc.add_niels(&base::ODD[entry]);
            } else if d < 0 {
                acc = acc.add_niels(&base::ODD[entry].neg());
            }
        }
        acc
    }

    /// The 32-byte encoding: y, with the sign of x in the top bit.
    fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut out = y.to_bytes();
        out[31] |= x.is_negative() << 7;
        out
    }

    /// Decoding per RFC 8032 section 5.1.3; `None` where it says to
    /// reject. Public data only, so the branches are fine.
    fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let sign = bytes[31] >> 7;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        if !below_prime(&y_bytes) {
            return None;
        }
        let y = Fe::from_bytes(&y_bytes);

        // x^2 = (y^2 - 1) / (d y^2 + 1). The root, when there is
        // one, is u v^3 (u v^7)^((p-5)/8), possibly times sqrt(-1).
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul(&D).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());

        let vxx = v.mul(&x.square());
        if vxx.equals(&u.neg()) {
            x = x.mul(&SQRT_M1);
        } else if !vxx.equals(&u) {
            return None;
        }

        // Zero has no sign, so the encoding claiming one is invalid.
        if x.is_zero() {
            if sign == 1 {
                return None;
            }
        } else if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }
}

/// Whether the 32 little-endian bytes name a value below 2^255 - 19,
/// as canonical decoding requires. The caller clears the sign bit.
fn below_prime(bytes: &[u8; 32]) -> bool {
    if bytes[0] < 0xed {
        return true;
    }
    if bytes[31] != 0x7f {
        return true;
    }
    bytes[1..31].iter().any(|&b| b != 0xff)
}

/// The group order l = 2^252 + 27742317777372353535851937790883648493,
/// as four little-endian words.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// -1/l modulo 2^64, the Montgomery constant.
const MU: u64 = 0xd2b51da312547e1b;

/// 2^256 modulo l. Montgomery-multiplying by it reduces a value.
const R1: [u64; 4] = [
    0xd6ec31748d98951d,
    0xc6ef5bf4737dcf70,
    0xfffffffffffffffe,
    0x0fffffffffffffff,
];

/// 2^512 modulo l, for converting into the Montgomery domain.
const R2: [u64; 4] = [
    0xa40611e3449c0f01,
    0xd00e1ba768859347,
    0xceec73d217f5be65,
    0x0399411b7c309a3d,
];

/// An integer modulo the group order, four little-endian words,
/// always fully reduced.
///
/// Products go through Montgomery multiplication: an extra
/// multiplication by 2^512 mod l puts the stray 2^-256 factor back,
/// which costs one more pass but keeps every value in plain form.
/// The arithmetic is a fixed sequence of word operations, with the
/// final subtraction chosen by a mask.
#[derive(Clone, Copy, Zeroize)]
struct Scalar([u64; 4]);

impl Scalar {
    /// Reads 32 bytes, reducing modulo l.
    fn from_bytes_reduced(bytes: &[u8; 32]) -> Scalar {
        Scalar::montmul(&load_words(bytes), &R1)
    }

    /// Reads 64 bytes, as SHA-512 leaves them, reducing modulo l.
    fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        let mut half = [0u8; 32];
        half.copy_from_slice(&bytes[..32]);
        let lo = Scalar::montmul(&load_words(&half), &R1);
        half.copy_from_slice(&bytes[32..]);
        let hi = Scalar::montmul(&load_words(&half), &R2);
        half.zeroize();
        lo.addmod(&hi)
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Whether the 32 bytes already name a value below l. Used on
    /// the public `s` of a signature, so it need not hide anything.
    fn is_below_order(bytes: &[u8; 32]) -> bool {
        let words = load_words(bytes);
        for i in (0..4).rev() {
            if words[i] < L[i] {
                return true;
            }
            if words[i] > L[i] {
                return false;
            }
        }
        false
    }

    /// `self * other * 2^-256 mod l`, the Montgomery product, by
    /// coarsely integrated operand scanning.
    fn montmul(a: &[u64; 4], b: &[u64; 4]) -> Scalar {
        let wide = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let mut t = [0u64; 6];
        for &ai in a {
            let mut carry = 0u64;
            for j in 0..4 {
                let v = u128::from(t[j]) + wide(ai, b[j]) + u128::from(carry);
                t[j] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(t[4]) + u128::from(carry);
            t[4] = v as u64;
            t[5] = (v >> 64) as u64;

            // Adding this multiple of l zeroes the low word, so the
            // whole value shifts down one word, exactly.
            let m = t[0].wrapping_mul(MU);
            let v = u128::from(t[0]) + wide(m, L[0]);
            debug_assert_eq!(v as u64, 0);
            let mut carry = (v >> 64) as u64;
            for j in 1..4 {
                let v = u128::from(t[j]) + wide(m, L[j]) + u128::from(carry);
                t[j - 1] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(t[4]) + u128::from(carry);
            t[3] = v as u64;
            let v = u128::from(t[5]) + (v >> 64);
            t[4] = v as u64;
            t[5] = 0;
        }
        // l is below 2^253, so the result is below 2l and fits four
        // words; at most one subtraction finishes the job.
        debug_assert_eq!(t[4], 0);
        Scalar::reduce_once([t[0], t[1], t[2], t[3]])
    }

    /// One conditional subtraction of l, chosen by a mask.
    fn reduce_once(t: [u64; 4]) -> Scalar {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = t[i].overflowing_sub(L[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            r[i] = d;
            borrow = u64::from(b1 | b2);
        }
        // A borrow out means t was already reduced: keep it.
        let keep = borrow.wrapping_neg();
        for i in 0..4 {
            r[i] ^= (r[i] ^ t[i]) & keep;
        }
        Scalar(r)
    }

    /// `self * other mod l`: two Montgomery passes, the second
    /// cancelling the first's 2^-256.
    fn mulmod(&self, other: &Scalar) -> Scalar {
        Scalar::montmul(&Scalar::montmul(&self.0, &other.0).0, &R2)
    }

    /// `self + other mod l`.
    fn addmod(&self, other: &Scalar) -> Scalar {
        let mut sum = [0u64; 4];
        let mut carry = 0u64;
        let terms = self.0.iter().zip(other.0);
        for (s, (a, b)) in sum.iter_mut().zip(terms) {
            let v = u128::from(*a) + u128::from(b) + u128::from(carry);
            *s = v as u64;
            carry = (v >> 64) as u64;
        }
        // Both inputs are below l < 2^253, so the sum fits.
        debug_assert_eq!(carry, 0);
        Scalar::reduce_once(sum)
    }
}

/// Reads 32 little-endian bytes as four words.
fn load_words(bytes: &[u8; 32]) -> [u64; 4] {
    let mut words = [0u64; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        *word = u64::from_le_bytes(buf);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::{CtrDrbg, MIN_SEED};

    /// The base point B: y = 4/5, x the even root for it. Signing
    /// reads its multiples from [`base`]; the tests check those
    /// against it, and the general multiplication against the comb.
    const BASE: Point = Point {
        x: Fe([
            0x62d608f25d51a,
            0x412a4b4f6592a,
            0x75b7171a4b31d,
            0x1ff60527118fe,
            0x216936d3cd6e5,
        ]),
        y: Fe([
            0x6666666666658,
            0x4cccccccccccc,
            0x1999999999999,
            0x3333333333333,
            0x6666666666666,
        ]),
        z: Fe::ONE,
        t: Fe([
            0x68ab3a5b7dda3,
            0x00eea2a5eadbb,
            0x2af8df483c27e,
            0x332b375274732,
            0x67875f0fd78b7,
        ]),
    };

    /// Decodes hex into `buf`, returning the filled prefix.
    fn unhex<'a>(hex: &str, buf: &'a mut [u8]) -> &'a [u8] {
        let hex = hex.as_bytes();
        assert!(hex.len().is_multiple_of(2));
        assert!(hex.len() / 2 <= buf.len());
        for (byte, pair) in buf.iter_mut().zip(hex.chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        &buf[..hex.len() / 2]
    }

    fn unhex32(hex: &str) -> [u8; 32] {
        let mut buf = [0u8; 32];
        unhex(hex, &mut buf);
        buf
    }

    fn unhex64(hex: &str) -> [u8; 64] {
        let mut buf = [0u8; 64];
        unhex(hex, &mut buf);
        buf
    }

    /// The RFC 8032 section 7.1 vectors: secret key, public key,
    /// message, signature. The 1023-byte message exercises multi
    /// block hashing; the last vector is SHA-512("abc").
    const VECTORS: &[(&str, &str, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc4\
             4449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a\
             0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f\
             5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc\
             9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540\
             a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c\
             387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b1\
             66d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f058\
             0816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a3\
             0ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc659\
             4a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "f5e5767cf153319517630f226876b86c\
             8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386\
             ceffbf2b2428c9c51fef7c597f1d426e",
            "08b8b2b733424243760fe426a4b54908\
             632110a66c2f6591eabd3345e3e4eb98\
             fa6e264bf09efe12ee50f8f54e9f77b1\
             e355f6c50544e23fb1433ddf73be84d8\
             79de7c0046dc4996d9e773f4bc9efe57\
             38829adb26c81b37c93a1b270b20329d\
             658675fc6ea534e0810a4432826bf58c\
             941efb65d57a338bbd2e26640f89ffbc\
             1a858efcb8550ee3a5e1998bd177e93a\
             7363c344fe6b199ee5d02e82d522c4fe\
             ba15452f80288a821a579116ec6dad2b\
             3b310da903401aa62100ab5d1a36553e\
             06203b33890cc9b832f79ef80560ccb9\
             a39ce767967ed628c6ad573cb116dbef\
             efd75499da96bd68a8a97b928a8bbc10\
             3b6621fcde2beca1231d206be6cd9ec7\
             aff6f6c94fcd7204ed3455c68c83f4a4\
             1da4af2b74ef5c53f1d8ac70bdcb7ed1\
             85ce81bd84359d44254d95629e9855a9\
             4a7c1958d1f8ada5d0532ed8a5aa3fb2\
             d17ba70eb6248e594e1a2297acbbb39d\
             502f1a8c6eb6f1ce22b3de1a1f40cc24\
             554119a831a9aad6079cad88425de6bd\
             e1a9187ebb6092cf67bf2b13fd65f270\
             88d78b7e883c8759d2c4f5c65adb7553\
             878ad575f9fad878e80a0c9ba63bcbcc\
             2732e69485bbc9c90bfbd62481d9089b\
             eccf80cfe2df16a2cf65bd92dd597b07\
             07e0917af48bbb75fed413d238f5555a\
             7a569d80c3414a8d0859dc65a46128ba\
             b27af87a71314f318c782b23ebfe808b\
             82b0ce26401d2e22f04d83d1255dc51a\
             ddd3b75a2b1ae0784504df543af8969b\
             e3ea7082ff7fc9888c144da2af58429e\
             c96031dbcad3dad9af0dcbaaaf268cb8\
             fcffead94f3c7ca495e056a9b47acdb7\
             51fb73e666c6c655ade8297297d07ad1\
             ba5e43f1bca32301651339e22904cc8c\
             42f58c30c04aafdb038dda0847dd988d\
             cda6f3bfd15c4b4c4525004aa06eeff8\
             ca61783aacec57fb3d1f92b0fe2fd1a8\
             5f6724517b65e614ad6808d6f6ee34df\
             f7310fdc82aebfd904b01e1dc54b2927\
             094b2db68d6f903b68401adebf5a7e08\
             d78ff4ef5d63653a65040cf9bfd4aca7\
             984a74d37145986780fc0b16ac451649\
             de6188a7dbdf191f64b5fc5e2ab47b57\
             f7f7276cd419c17a3ca8e1b939ae49e4\
             88acba6b965610b5480109c8b17b80e1\
             b7b750dfc7598d5d5011fd2dcc5600a3\
             2ef5b52a1ecc820e308aa342721aac09\
             43bf6686b64b2579376504ccc493d97e\
             6aed3fb0f9cd71a43dd497f01f17c0e2\
             cb3797aa2a2f256656168e6c496afc5f\
             b93246f6b1116398a346f1a641f3b041\
             e989f7914f90cc2c7fff357876e506b5\
             0d334ba77c225bc307ba537152f3f161\
             0e4eafe595f6d9d90d11faa933a15ef1\
             369546868a7f3a45a96768d40fd9d034\
             12c091c6315cf4fde7cb68606937380d\
             b2eaaa707b4c4185c32eddcdd306705e\
             4dc1ffc872eeee475a64dfac86aba41c\
             0618983f8741c5ef68d3a101e8a3b8ca\
             c60c905c15fc910840b94c00a0b9d0",
            "0aab4c900501b3e24d7cdf4663326a3a\
             87df5e4843b2cbdb67cbf6e460fec350\
             aa5371b1508f9f4528ecea23c436d94b\
             5e8fcd4f681e30a6ac00a9704a188a03",
        ),
        (
            "833fe62409237b9d62ec77587520911e\
             9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034\
             c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae204131\
             12e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00\
             201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e030\
             3dca179c138ac17ad9bef1177331a704",
        ),
    ];

    /// The hedged nonce, rebuilt by hand from the draft's text
    /// (draft-irtf-cfrg-det-sigs-with-noise-05 section 3): the prefix
    /// becomes the first half of SHA-512(prefix || Z), and the
    /// signature's R is the base point times the nonce made from it.
    /// The draft has no vectors yet, so this pins the construction.
    #[test]
    fn hedged_nonce_by_hand() {
        let secret = [0x5au8; KEY_SIZE];
        let z = [0xc3u8; 32];
        let head = dom2(CTX, b"use").unwrap();
        for dom in [&[][..], &[&head[..], b"use"][..]] {
            let signature =
                sign_with(&secret, &public_key(&secret), dom, b"m", Some(&z));
            let h = Sha512::digest(&secret);
            let mut mixed = Sha512::new();
            mixed.update(&h[32..]);
            mixed.update(&z);
            let mixed = mixed.finalize();
            let mut nonce = Sha512::new();
            for part in dom {
                nonce.update(part);
            }
            nonce.update(&mixed[..32]);
            nonce.update(b"m");
            let r = Scalar::from_bytes_wide(&nonce.finalize());
            assert_eq!(signature[..32], Point::mul_base(&r).compress());
        }
    }

    /// Hedged signatures verify under every variant, differ from the
    /// deterministic ones and from each other, and the deterministic
    /// forms still repeat.
    #[test]
    fn hedged_signatures_verify() {
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = PrivateKey::new(&Key::from([0x77u8; KEY_SIZE]));
        let public = key.public_key();
        let a = key.sign(&mut rng, b"m").unwrap();
        let b = key.sign(&mut rng, b"m").unwrap();
        public.verify(b"m", &a).unwrap();
        public.verify(b"m", &b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, key.sign_deterministic(b"m"));
        assert_eq!(key.sign_deterministic(b"m"), key.sign_deterministic(b"m"));
        let ctx = key.sign_ctx(&mut rng, b"use", b"m").unwrap();
        public.verify_ctx(b"use", b"m", &ctx).unwrap();
        assert_ne!(ctx, key.sign_ctx_deterministic(b"use", b"m").unwrap());
        let prehash = Sha512::digest(b"m");
        let ph = key.sign_ph(&mut rng, b"", &prehash).unwrap();
        public.verify_ph(b"", &prehash, &ph).unwrap();
        // The free functions hedge the same way.
        let seed = [0x77u8; KEY_SIZE];
        let free = sign(&seed, &mut rng, b"m").unwrap();
        verify(&public.bytes(), b"m", &free).unwrap();
        assert_ne!(free, a);
    }

    /// The key types are the free functions with the secret held in
    /// something that wipes itself, so they must agree at every step,
    /// and the pair encoding must read back as what it wrote.
    #[test]
    fn key_types_match_the_functions() {
        let seed = [0x9du8; KEY_SIZE];
        let key = PrivateKey::new(&Key::from(seed));
        assert_eq!(key.secret_bytes(), seed);
        assert_eq!(key.public_key().bytes(), public_key(&seed));

        let message = b"the message";
        let signature = key.sign_deterministic(message);
        assert_eq!(signature, sign_deterministic(&seed, message));
        key.public_key()
            .verify(message, &signature)
            .expect("verify");
        assert_eq!(
            key.public_key().verify(b"another", &signature),
            Err(Error::InvalidSignature)
        );

        // The version 1 encoding carries the public key, and reading
        // it back checks the pair agrees.
        let der = key.der_bytes();
        let read = PrivateKey::try_from_der(&der).expect("der");
        assert_eq!(read.secret_bytes(), seed);
        assert_eq!(read.public_key(), key.public_key());
        let pem = key.pem_bytes();
        assert_eq!(
            PrivateKey::try_from_pem(&pem).unwrap().secret_bytes(),
            seed
        );

        // The version 0 form still reads, and is the shorter one.
        assert!(secret_der(&seed).len() < der.len());
        let short = PrivateKey::try_from_der(&secret_der(&seed)).expect("v0");
        assert_eq!(short.public_key(), key.public_key());

        // A public key round-trips through both encodings.
        let public = *key.public_key();
        assert_eq!(
            PublicKey::try_from_der(&public.der_bytes()).unwrap(),
            public
        );
        assert_eq!(
            PublicKey::try_from_pem(&public.pem_bytes()).unwrap(),
            public
        );
    }

    /// A drawn key takes its whole seed from the source.
    #[test]
    fn generate_draws_the_seed() {
        let mut rng = CtrDrbg::from_seed(&[0x33u8; MIN_SEED]).expect("seed");
        let one = PrivateKey::generate(&mut rng).expect("one");
        let two = PrivateKey::generate(&mut rng).expect("two");
        assert_ne!(one.secret_bytes(), two.secret_bytes());
        assert_ne!(one.public_key(), two.public_key());
        assert_eq!(one.public_key().bytes(), public_key(&one.secret_bytes()));
    }

    #[test]
    fn rfc8032_vectors() {
        let mut msg_buf = [0u8; 1024];
        for (sk, pk, msg, sig) in VECTORS {
            let secret = unhex32(sk);
            let expected_public = unhex32(pk);
            let message = unhex(msg, &mut msg_buf);
            let expected_sig = unhex64(sig);

            assert_eq!(public_key(&secret), expected_public);
            let signature = sign_deterministic(&secret, message);
            assert_eq!(signature, expected_sig);
            assert_eq!(verify(&expected_public, message, &signature), Ok(()),);
        }
    }

    /// The RFC 8032 section 7.2 Ed25519ctx vectors: secret key,
    /// public key, message, context, signature.
    const CTX_VECTORS: &[(&str, &str, &str, &str, &str)] = &[
        (
            "0305334e381af78f141cb666f6199f57\
             bc3495335a256a95bd2a55bf546663f6",
            "dfc9425e4f968f7f0c29f0259cf5f9ae\
             d6851c2bb4ad8bfb860cfee0ab248292",
            "f726936d19c800494e3fdaff20b276a8",
            "666f6f",
            "55a4cc2f70a54e04288c5f4cd1e45a7b\
             b520b36292911876cada7323198dd87a\
             8b36950b95130022907a7fb7c4e9b2d5\
             f6cca685a587b4b21f4b888e4e7edb0d",
        ),
        (
            "0305334e381af78f141cb666f6199f57\
             bc3495335a256a95bd2a55bf546663f6",
            "dfc9425e4f968f7f0c29f0259cf5f9ae\
             d6851c2bb4ad8bfb860cfee0ab248292",
            "f726936d19c800494e3fdaff20b276a8",
            "626172",
            "fc60d5872fc46b3aa69f8b5b4351d580\
             8f92bcc044606db097abab6dbcb1aee3\
             216c48e8b3b66431b5b186d1d28f8ee1\
             5a5ca2df6668346291c2043d4eb3e90d",
        ),
        (
            "0305334e381af78f141cb666f6199f57\
             bc3495335a256a95bd2a55bf546663f6",
            "dfc9425e4f968f7f0c29f0259cf5f9ae\
             d6851c2bb4ad8bfb860cfee0ab248292",
            "508e9e6882b979fea900f62adceaca35",
            "666f6f",
            "8b70c1cc8310e1de20ac53ce28ae6e72\
             07f33c3295e03bb5c0732a1d20dc6490\
             8922a8b052cf99b7c4fe107a5abb5b2c\
             4085ae75890d02df26269d8945f84b0b",
        ),
        (
            "ab9c2853ce297ddab85c993b3ae14bca\
             d39b2c682beabc27d6d4eb20711d6560",
            "0f1d1274943b91415889152e893d80e9\
             3275a1fc0b65fd71b4b0dda10ad7d772",
            "f726936d19c800494e3fdaff20b276a8",
            "666f6f",
            "21655b5f1aa965996b3f97b3c849eafb\
             a922a0a62992f73b3d1b73106a84ad85\
             e9b86a7b6005ea868337ff2d20a7f5fb\
             d4cd10b0be49a68da2b2e0dc0ad8960f",
        ),
    ];

    #[test]
    fn rfc8032_ctx_vectors() {
        let mut message_buf = [0u8; 16];
        let mut context_buf = [0u8; 3];
        for (sk, pk, msg, ctx, sig) in CTX_VECTORS {
            let secret = unhex32(sk);
            let public = unhex32(pk);
            let message = unhex(msg, &mut message_buf);
            let context = unhex(ctx, &mut context_buf);
            let expected = unhex64(sig);
            assert_eq!(public_key(&secret), public);
            assert_eq!(
                sign_ctx_deterministic(&secret, context, message),
                Ok(expected)
            );
            assert_eq!(
                verify_ctx(&public, context, message, &expected),
                Ok(())
            );
        }
    }

    /// The RFC 8032 section 7.3 Ed25519ph vector, whose message is
    /// "abc" and whose context is empty.
    #[test]
    fn rfc8032_ph_vector() {
        let secret = unhex32(
            "833fe62409237b9d62ec77587520911e\
             9a759cec1d19755b7da901b96dca3d42",
        );
        let public = unhex32(
            "ec172b93ad5e563bf4932c70e1245034\
             c35467ef2efd4d64ebf819683467e2bf",
        );
        let expected = unhex64(
            "98a70222f0b8121aa9d30f813d683f80\
             9e462b469c7ff87639499bb94e6dae41\
             31f85042463c2a355a2003d062adf5aa\
             a10b8c61e636062aaad11c2a26083406",
        );
        let prehash = Sha512::digest(b"abc");
        assert_eq!(public_key(&secret), public);
        assert_eq!(sign_ph_deterministic(&secret, b"", &prehash), Ok(expected));
        assert_eq!(verify_ph(&public, b"", &prehash, &expected), Ok(()));
    }

    /// Ed25519ctx takes 1 to 255 bytes of context and Ed25519ph 0 to
    /// 255, signing and verifying alike; the refusal is the length.
    #[test]
    fn context_lengths() {
        let secret = [0x5au8; KEY_SIZE];
        let public = public_key(&secret);
        let prehash = [0x17u8; PREHASH_SIZE];
        let long = [0x33u8; CONTEXT_MAX + 1];
        let signature = [0u8; SIGNATURE_SIZE];

        assert_eq!(
            sign_ctx_deterministic(&secret, b"", b"m"),
            Err(Error::InvalidLength(0))
        );
        assert_eq!(
            verify_ctx(&public, b"", b"m", &signature),
            Err(Error::InvalidLength(0))
        );
        assert_eq!(
            sign_ctx_deterministic(&secret, &long, b"m"),
            Err(Error::InvalidLength(256))
        );
        assert_eq!(
            sign_ph_deterministic(&secret, &long, &prehash),
            Err(Error::InvalidLength(256))
        );
        assert_eq!(
            verify_ph(&public, &long, &prehash, &signature),
            Err(Error::InvalidLength(256))
        );

        for context in [&long[..1], &long[..CONTEXT_MAX]] {
            let signature =
                sign_ctx_deterministic(&secret, context, b"m").unwrap();
            assert_eq!(verify_ctx(&public, context, b"m", &signature), Ok(()));
        }
        for context in [&long[..0], &long[..CONTEXT_MAX]] {
            let signature =
                sign_ph_deterministic(&secret, context, &prehash).unwrap();
            assert_eq!(
                verify_ph(&public, context, &prehash, &signature),
                Ok(())
            );
        }
    }

    /// No variant accepts another's signature over the same bytes,
    /// and no context accepts another's: the domain prefix is in both
    /// hashes, so each is a different signature.
    #[test]
    fn variants_and_contexts_are_separate() {
        let secret = [0x61u8; KEY_SIZE];
        let public = public_key(&secret);
        let bytes = [0x2cu8; PREHASH_SIZE];

        let plain = sign_deterministic(&secret, &bytes);
        let ctx = sign_ctx_deterministic(&secret, b"foo", &bytes).unwrap();
        let ph_empty = sign_ph_deterministic(&secret, b"", &bytes).unwrap();
        let ph_foo = sign_ph_deterministic(&secret, b"foo", &bytes).unwrap();

        let bad = Err(Error::InvalidSignature);
        assert_eq!(verify_ctx(&public, b"foo", &bytes, &plain), bad);
        assert_eq!(verify_ph(&public, b"", &bytes, &plain), bad);
        assert_eq!(verify(&public, &bytes, &ctx), bad);
        assert_eq!(verify_ctx(&public, b"bar", &bytes, &ctx), bad);
        assert_eq!(verify_ph(&public, b"foo", &bytes, &ctx), bad);
        assert_eq!(verify(&public, &bytes, &ph_empty), bad);
        assert_eq!(verify_ph(&public, b"foo", &bytes, &ph_empty), bad);
        assert_eq!(verify_ctx(&public, b"foo", &bytes, &ph_foo), bad);

        // Ed25519ph signs the digest it is given, not a hash of it.
        let hashed = Sha512::digest(&bytes);
        assert_eq!(verify_ph(&public, b"", &hashed, &ph_empty), bad);
    }

    /// The key types' variants are the free functions with the public
    /// key already derived.
    #[test]
    fn key_types_match_the_variant_functions() {
        let seed = [0x4eu8; KEY_SIZE];
        let key = PrivateKey::new(&Key::from(seed));
        let prehash = [0x09u8; PREHASH_SIZE];

        let ctx = key.sign_ctx_deterministic(b"use", b"message").unwrap();
        assert_eq!(sign_ctx_deterministic(&seed, b"use", b"message"), Ok(ctx));
        assert_eq!(
            key.public_key().verify_ctx(b"use", b"message", &ctx),
            Ok(())
        );
        assert_eq!(
            key.sign_ctx_deterministic(b"", b"message"),
            Err(Error::InvalidLength(0))
        );

        let ph = key.sign_ph_deterministic(b"use", &prehash).unwrap();
        assert_eq!(sign_ph_deterministic(&seed, b"use", &prehash), Ok(ph));
        assert_eq!(key.public_key().verify_ph(b"use", &prehash, &ph), Ok(()));
        assert_eq!(
            key.public_key().verify_ph(b"other", &prehash, &ph),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn rejects_tampering() {
        let (sk, pk, _, _) = VECTORS[2];
        let secret = unhex32(sk);
        let public = unhex32(pk);
        let message = *b"af82 is not this message";
        let signature = sign_deterministic(&secret, &message);
        assert_eq!(verify(&public, &message, &signature), Ok(()));

        let mut wrong = message;
        wrong[0] ^= 1;
        assert_eq!(
            verify(&public, &wrong, &signature),
            Err(Error::InvalidSignature),
        );

        for byte in [0, 31, 32, 63] {
            let mut bad = signature;
            bad[byte] ^= 1;
            assert_eq!(
                verify(&public, &message, &bad),
                Err(Error::InvalidSignature),
            );
        }
    }

    /// Adding the group order to s gives the classic malleated twin,
    /// which RFC 8032's range check refuses.
    #[test]
    fn rejects_high_s() {
        let (sk, pk, msg, _) = VECTORS[1];
        let secret = unhex32(sk);
        let public = unhex32(pk);
        let mut msg_buf = [0u8; 4];
        let message = unhex(msg, &mut msg_buf);
        let mut signature = sign_deterministic(&secret, message);
        let l_bytes = {
            let mut out = [0u8; 32];
            for (chunk, word) in out.chunks_exact_mut(8).zip(L) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            out
        };
        let mut carry = 0u16;
        for i in 0..32 {
            let v =
                u16::from(signature[32 + i]) + u16::from(l_bytes[i]) + carry;
            signature[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "s + l still fits 32 bytes");
        assert_eq!(
            verify(&public, message, &signature),
            Err(Error::InvalidSignature),
        );
    }

    #[test]
    fn rejects_undecodable_public_key() {
        let (_, _, _, sig) = VECTORS[0];
        let signature = unhex64(sig);
        // y = 2^255 - 1 is not below the prime.
        let mut public = [0xffu8; 32];
        public[31] = 0x7f;
        assert_eq!(
            verify(&public, b"", &signature),
            Err(Error::InvalidPublicKey),
        );
    }

    /// The scalar field's corners: reduction of the wide hash, and
    /// the boundary of the order check.
    #[test]
    fn scalar_arithmetic_corners() {
        // l itself is not below l; l - 1 is.
        let mut l_bytes = [0u8; 32];
        for (chunk, word) in l_bytes.chunks_exact_mut(8).zip(L) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        assert!(!Scalar::is_below_order(&l_bytes));
        let mut l_minus_1 = l_bytes;
        l_minus_1[0] -= 1;
        assert!(Scalar::is_below_order(&l_minus_1));

        // l reduces to zero, and l - 1 stays put.
        assert_eq!(Scalar::from_bytes_reduced(&l_bytes).to_bytes(), [0u8; 32],);
        assert_eq!(
            Scalar::from_bytes_reduced(&l_minus_1).to_bytes(),
            l_minus_1,
        );

        // (l - 1) * (l - 1) = 1 mod l, since l - 1 = -1.
        let minus_one = Scalar::from_bytes_reduced(&l_minus_1);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(minus_one.mulmod(&minus_one).to_bytes(), one);
        // And -1 + 1 = 0.
        let unit = Scalar::from_bytes_reduced(&one);
        assert_eq!(minus_one.addmod(&unit).to_bytes(), [0u8; 32]);
    }

    /// Compression inverts decompression on the base point, and
    /// scalar multiplication by the order gives the identity.
    #[test]
    fn point_roundtrip_and_order() {
        let encoded = BASE.compress();
        let decoded = Point::decompress(&encoded).unwrap();
        assert_eq!(decoded.compress(), encoded);

        let mut one = [0u8; 32];
        one[0] = 1;
        let unit = Scalar::from_bytes_reduced(&one);
        let same = ladder(&BASE, &unit);
        assert_eq!(same.compress(), encoded);

        // l * B is the identity, whose encoding is y = 1.
        let zero = Scalar([0; 4]);
        let identity = ladder(&BASE, &zero);
        assert_eq!(identity.compress(), Point::IDENTITY.compress());
    }

    /// Every entry of the comb table is the multiple of `B` it
    /// stands for: the sum of `2^(i * d) B` over the set bits of its
    /// index, as `y + x`, `y - x` and `2dxy`. This is what says the
    /// checked-in table is the curve's and not something else.
    #[test]
    fn base_table_is_multiples_of_b() {
        let mut bases = [BASE; COMB];
        for i in 1..COMB {
            let mut p = bases[i - 1];
            for _ in 0..BLOCK {
                p = p.double();
            }
            bases[i] = p;
        }
        assert_eq!(base::BASE.len(), (1 << COMB) - 1);
        for (j, entry) in base::BASE.iter().enumerate() {
            let index = j + 1;
            let mut sum = Point::IDENTITY;
            for (i, b) in bases.iter().enumerate() {
                if index >> i & 1 == 1 {
                    sum = sum.add(b);
                }
            }
            let zinv = sum.z.invert();
            let x = sum.x.mul(&zinv);
            let y = sum.y.mul(&zinv);
            let xy2d = x.mul(&y).mul(&D2);
            for (want, got) in [
                (y.add(&x), entry.y_plus_x),
                (y.sub(&x), entry.y_minus_x),
                (xy2d, entry.xy2d),
            ] {
                assert_eq!(want.to_bytes(), got.to_bytes(), "{index}");
                // Canonical limbs, which the formulas' bounds assume.
                assert!(got.0.iter().all(|&limb| limb < 1 << 51));
            }
        }
    }

    /// The comb agrees with the general multiplication over the
    /// scalars that reach its edges.
    #[test]
    fn mul_base_matches_the_general_multiplication() {
        for k in edge_scalars() {
            assert_eq!(
                Point::mul_base(&k).compress(),
                ladder(&BASE, &k).compress(),
            );
        }
    }

    /// `scalar` times `p`, a bit at a time: slow and plainly right,
    /// the reference the faster multiplications are held to.
    fn ladder(p: &Point, scalar: &Scalar) -> Point {
        let bytes = scalar.to_bytes();
        let mut acc = Point::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            if (bytes[i >> 3] >> (i & 7)) & 1 == 1 {
                acc = acc.add(p);
            }
        }
        acc
    }

    /// Scalars at the edges of a digit expansion: zero, one, the
    /// order less one, the top bit a reduced scalar can have, a
    /// spread of bits that reaches every block and window, and runs
    /// of ones that carry across the whole width.
    fn edge_scalars() -> [Scalar; 7] {
        let mut top = L;
        top[0] -= 1;
        let high = [0, 0, 0, 1 << 60];
        let mut spread = [0u64; 4];
        for (i, word) in spread.iter_mut().enumerate() {
            *word = 0x0f1e2d3c4b5a6978u64.rotate_left(i as u32 * 7);
        }
        spread[3] &= (1 << 60) - 1;
        let ones = [u64::MAX, u64::MAX, u64::MAX, (1 << 60) - 1];
        let mut alternate = [0xaaaa_aaaa_aaaa_aaaa; 4];
        alternate[3] &= (1 << 60) - 1;
        [
            Scalar([0; 4]),
            Scalar([1, 0, 0, 0]),
            Scalar(top),
            Scalar(high),
            Scalar(spread),
            Scalar(ones),
            Scalar(alternate),
        ]
    }

    /// The digits have the shape the multiplication relies on, odd
    /// and bounded and spaced, and add back up to the scalar.
    #[test]
    fn naf_digits_are_the_scalar() {
        for width in [A_WIDTH, B_WIDTH] {
            for k in edge_scalars() {
                let digits = naf(&k, width);
                let bound = 1i16 << (width - 1);
                let mut last = None;
                // The sum, in five words of two's complement.
                let mut sum = [0u64; 5];
                for (i, &d) in digits.iter().enumerate() {
                    if d == 0 {
                        continue;
                    }
                    assert_eq!(d & 1, 1, "{width} {i}: even digit");
                    assert!(i16::from(d).abs() < bound, "{width} {i}");
                    if let Some(last) = last {
                        assert!(i - last >= width as usize, "{width} {i}");
                    }
                    last = Some(i);
                    shifted_add(&mut sum, i64::from(d), i);
                }
                assert_eq!(sum[..4], k.0, "{width}");
                assert_eq!(sum[4], 0, "{width}");
            }
        }
    }

    /// `sum += value * 2^shift`, modulo 2^320.
    fn shifted_add(sum: &mut [u64; 5], value: i64, shift: usize) {
        // The value sign-extended across all five words, then shifted.
        let fill = if value < 0 { u64::MAX } else { 0 };
        let mut wide = [value as u64, fill, fill, fill, fill];
        for _ in 0..shift {
            for j in (1..5).rev() {
                wide[j] = (wide[j] << 1) | (wide[j - 1] >> 63);
            }
            wide[0] <<= 1;
        }
        let mut carry = 0u64;
        for (s, w) in sum.iter_mut().zip(wide) {
            let (a, c1) = s.overflowing_add(w);
            let (b, c2) = a.overflowing_add(carry);
            *s = b;
            carry = u64::from(c1 | c2);
        }
    }

    /// Entry `i` of the odd table is `(2i + 1) B`, and every limb is
    /// canonical, as the addition's bounds assume.
    #[test]
    fn odd_table_is_odd_multiples_of_b() {
        let twice = BASE.double();
        let mut p = BASE;
        for (i, entry) in base::ODD.iter().enumerate() {
            let zinv = p.z.invert();
            let x = p.x.mul(&zinv);
            let y = p.y.mul(&zinv);
            let xy2d = x.mul(&y).mul(&D2);
            for (want, got) in [
                (y.add(&x), entry.y_plus_x),
                (y.sub(&x), entry.y_minus_x),
                (xy2d, entry.xy2d),
            ] {
                assert_eq!(want.to_bytes(), got.to_bytes(), "{i}");
                assert!(got.0.iter().all(|&limb| limb < 1 << 51));
            }
            p = p.add(&twice);
        }
    }

    /// The joint multiplication is the sum of the two it replaces,
    /// over every pair of edge scalars, for the base point itself and
    /// for a public key from RFC 8032, negated as verification
    /// negates it.
    #[test]
    fn mul_add_base_matches_the_separate_multiplications() {
        let key = Point::decompress(&unhex32(VECTORS[1].1)).expect("key");
        for p in [BASE, key.neg()] {
            for a in edge_scalars() {
                for b in edge_scalars() {
                    let want = ladder(&p, &a).add(&ladder(&BASE, &b));
                    assert_eq!(
                        p.mul_add_base_vartime(&a, &b).compress(),
                        want.compress(),
                    );
                }
            }
        }
    }

    /// RFC 8410 section 10: the example private key in both its
    /// version 0 and version 1 forms, with the attributes the second
    /// carries, and the matching public key from section 10.1.
    #[test]
    fn rfc8410_examples() {
        let v0 = b"-----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
            -----END PRIVATE KEY-----\n";
        let v1 = b"-----BEGIN PRIVATE KEY-----\n\
            MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
            oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n\
            Z9w7lshQhqowtrbLDFw4rXAxZuE=\n\
            -----END PRIVATE KEY-----\n";
        let public = b"-----BEGIN PUBLIC KEY-----\n\
            MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
            -----END PUBLIC KEY-----\n";
        let secret = secret_from_pem(v0).unwrap();
        assert_eq!(
            secret,
            unhex32(
                "d4ee72dbf913584ad5b6d8f1f769f8ad\
                 3afe7c28cbf1d4fbe097a88f44755842"
            )
        );
        assert_eq!(secret_from_pem(v1), Ok(secret));
        let pk = public_key_from_pem(public).unwrap();
        assert_eq!(public_key(&secret), pk);
        assert_eq!(secret_pem(&secret)[..], v0[..]);
        assert_eq!(public_key_pem(&pk)[..], public[..]);

        // The version 1 form with its public key altered is a pair
        // that disagrees.
        let mut wrong = *v1;
        let i = wrong.iter().rposition(|&c| c == b'=').unwrap() - 1;
        wrong[i] = if wrong[i] == b'E' { b'F' } else { b'E' };
        assert_eq!(secret_from_pem(&wrong), Err(Error::InvalidEncoding));
    }

    /// What OpenSSL 3.5 writes for a fresh key, from
    /// `openssl genpkey -algorithm Ed25519` and `openssl pkey
    /// -outform DER`, with and without `-pubout`.
    /// The form is reported: version 0, version 1 without a public
    /// key, and version 1 with one. A NULL parameter is another
    /// algorithm's identifier, and a version past 1 is not read.
    #[test]
    fn the_form_of_a_private_key_info_is_reported() {
        let secret = [0x11u8; 32];
        let v0 = secret_der(&secret);
        assert_eq!(
            secret_from_der_with_form(&v0),
            Ok((
                secret,
                Pkcs8Form {
                    v1: false,
                    public_key: false
                }
            ))
        );
        let pair = PrivateKey::new(&Key::from(secret)).der_bytes();
        assert_eq!(
            secret_from_der_with_form(&pair).map(|(_, f)| f),
            Ok(Pkcs8Form {
                v1: true,
                public_key: true
            })
        );
        // Version 1 with the public key left out: legal, and said.
        let mut v1 = v0;
        v1[4] = 1;
        assert_eq!(
            secret_from_der_with_form(&v1).map(|(_, f)| f),
            Ok(Pkcs8Form {
                v1: true,
                public_key: false
            })
        );
        v1[4] = 2;
        assert_eq!(secret_from_der(&v1), Err(Error::UnsupportedVersion));

        let mut with_null = [0u8; 50];
        with_null[..18].copy_from_slice(&[
            0x30, 48, 0x02, 1, 0, 0x30, 7, 0x06, 3, 0x2b, 0x65, 0x70, 0x05, 0,
            0x04, 34, 0x04, 32,
        ]);
        with_null[18..].copy_from_slice(&secret);
        assert_eq!(secret_from_der(&with_null), Err(Error::WrongAlgorithm));
    }

    #[test]
    fn openssl_encodings() {
        let mut secret_der_buf = [0u8; DER_SIZE];
        let secret_der_bytes = unhex(
            "302e020100300506032b657004220420\
             c22c00218a30664a9ca527dfcda3ab36\
             4ba3ac80a1960cc83dbc021e1557dcce",
            &mut secret_der_buf,
        );
        let mut public_der_buf = [0u8; PUBLIC_KEY_DER_SIZE];
        let public_der_bytes = unhex(
            "302a300506032b6570032100\
             52d3bd217410a127c572f332899e23ff\
             149fc234df6d9a86f24e4aeeb86c7b91",
            &mut public_der_buf,
        );
        let secret = secret_from_der(secret_der_bytes).unwrap();
        let public = public_key_from_der(public_der_bytes).unwrap();
        assert_eq!(public_key(&secret), public);
        assert_eq!(secret_der(&secret)[..], secret_der_bytes[..]);
        assert_eq!(public_key_der(&public)[..], public_der_bytes[..]);
        assert_eq!(secret_from_pem(&secret_pem(&secret)), Ok(secret));
        assert_eq!(public_key_from_pem(&public_key_pem(&public)), Ok(public));

        // An X25519 key is not an Ed25519 key.
        let mut x = *secret_der_bytes.first_chunk::<DER_SIZE>().unwrap();
        x[11] = 0x6e;
        assert_eq!(secret_from_der(&x), Err(Error::WrongAlgorithm));
        let mut x = *public_der_bytes
            .first_chunk::<PUBLIC_KEY_DER_SIZE>()
            .unwrap();
        x[8] = 0x6e;
        assert_eq!(public_key_from_der(&x), Err(Error::WrongAlgorithm));
    }
}
