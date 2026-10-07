//! HPKE (RFC 9180): hybrid public-key encryption, in base mode.
//!
//! The sender encapsulates a fresh shared secret to the recipient's
//! public key, sends the encapsulation, and from then on encrypts
//! with an AEAD keyed from that secret; the recipient decapsulates
//! with the private key and decrypts. Neither side needs to have
//! heard from the other first, which is what makes it the encryption
//! of Encrypted Client Hello, MLS and Oblivious HTTP.
//!
//! A suite is three choices. The KEM is the module: [`x25519`],
//! [`p256`], [`p384`] or [`p521`], each a DHKEM over that group with
//! the hash RFC 9180 pairs with it. The KDF and the AEAD are type
//! parameters on the calls that set up a context: any of
//! [`Sha256`], [`Sha384`] and [`Sha512`], and any of
//! `Gcm<Aes128>`, `Gcm<Aes256>` and [`ChaCha20Poly1305`].
//!
//! ```
//! use scytale::aead::{ChaCha20Poly1305, Gcm};
//! use scytale::cipher::aes::Aes128;
//! use scytale::hash::sha2::Sha256;
//! use scytale::pke::hpke::x25519::PrivateKey;
//! use scytale::random::CtrDrbg;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let recipient = PrivateKey::generate(&mut rng)?;
//!
//! // The sender needs only the public key and the context string
//! // both sides agree on.
//! let (enc, mut sender) = recipient
//!     .public_key()
//!     .sender::<Sha256, Gcm<Aes128>, _>(&mut rng, b"app v1")?;
//! let mut message = *b"attack at dawn";
//! let mut tag = [0u8; 16];
//! sender.encrypt(b"header", &mut message, &mut tag)?;
//!
//! // The recipient rebuilds the context from the encapsulation.
//! let mut receiver =
//!     recipient.recipient::<Sha256, Gcm<Aes128>>(&enc, b"app v1")?;
//! receiver.decrypt(b"header", &mut message, &tag)?;
//! assert_eq!(&message, b"attack at dawn");
//! # let _ = ChaCha20Poly1305::new;
//! # Ok(())
//! # }
//! ```
//!
//! Each context numbers its messages, and the nonce of each is the
//! context's base nonce with that number XORed in, so the two sides
//! must process messages in the same order. A context also derives
//! keys of its own through [`Context::export`].
//!
//! # What is not here
//!
//! The PSK and authenticated modes, which bind the sender's own key
//! or a pre-shared secret into the schedule, and the export-only
//! AEAD. Base mode is what ECH, Oblivious HTTP and most of MLS use.
//!
//! [`Sha256`]: crate::hash::sha2::Sha256
//! [`Sha384`]: crate::hash::sha2::Sha384
//! [`Sha512`]: crate::hash::sha2::Sha512
//! [`ChaCha20Poly1305`]: crate::aead::ChaCha20Poly1305

use core::marker::PhantomData;

use crate::aead::{Aead, ChaCha20Poly1305, Gcm};
use crate::cipher::aes::{Aes128, Aes256};
use crate::hash::Hash;
use crate::hash::sha2::{Sha256, Sha384, Sha512};
use crate::kdf::hkdf;
use crate::mac::Mac;
use crate::mac::hmac::Hmac;
use crate::{BlockType, Error};
use zeroize::Zeroize;

mod sealed {
    pub trait Sealed {}
}

/// A hash HPKE's key schedule may run HKDF over, with its RFC 9180
/// identifier. Implemented for SHA-256, SHA-384 and SHA-512 only.
pub trait Kdf:
    sealed::Sealed + Hash + Clone + BlockType + Default + 'static
{
    /// The `kdf_id` of RFC 9180 section 7.2.
    fn kdf_id() -> u16;
}

/// An AEAD a context may encrypt with, with its RFC 9180 identifier.
/// Implemented for AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
pub trait Cipher:
    sealed::Sealed + Aead<Nonce = [u8; NONCE_SIZE], Tag = [u8; TAG_SIZE]>
{
    /// The `aead_id` of RFC 9180 section 7.3.
    fn aead_id() -> u16;
}

impl sealed::Sealed for Sha256 {}
impl sealed::Sealed for Sha384 {}
impl sealed::Sealed for Sha512 {}
impl sealed::Sealed for Gcm<Aes128> {}
impl sealed::Sealed for Gcm<Aes256> {}
impl sealed::Sealed for ChaCha20Poly1305 {}

impl Kdf for Sha256 {
    fn kdf_id() -> u16 {
        0x0001
    }
}

impl Kdf for Sha384 {
    fn kdf_id() -> u16 {
        0x0002
    }
}

impl Kdf for Sha512 {
    fn kdf_id() -> u16 {
        0x0003
    }
}

impl Cipher for Gcm<Aes128> {
    fn aead_id() -> u16 {
        0x0001
    }
}

impl Cipher for Gcm<Aes256> {
    fn aead_id() -> u16 {
        0x0002
    }
}

impl Cipher for ChaCha20Poly1305 {
    fn aead_id() -> u16 {
        0x0003
    }
}

/// The length of every nonce here, `Nn`.
pub const NONCE_SIZE: usize = 12;

/// The length of every tag here, `Nt`.
pub const TAG_SIZE: usize = 16;

/// The longest digest a KDF here has, SHA-512's.
const MAX_HASH: usize = 64;

/// What every label is prefixed with (RFC 9180 section 4).
const VERSION: &[u8] = b"HPKE-v1";

/// `LabeledExtract(salt, label, ikm)`.
fn labeled_extract<H: Kdf>(
    suite: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> H::Output {
    let mut mac = Hmac::<H>::new(salt);
    mac.update(VERSION);
    mac.update(suite);
    mac.update(label);
    mac.update(ikm);
    mac.finalize()
}

/// `LabeledExpand(prk, label, info, L)`, the length `L` being the
/// output's; `info` comes in parts, joined in order.
fn labeled_expand<H: Kdf>(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    let len = u16::try_from(out.len())
        .map_err(|_| Error::InvalidLength(out.len()))?
        .to_be_bytes();
    let mut parts: [&[u8]; 8] = [&[]; 8];
    parts[..4].copy_from_slice(&[&len[..], VERSION, suite, label]);
    let count = 4 + info.len();
    parts
        .get_mut(4..count)
        .ok_or(Error::InvalidLength(info.len()))?
        .copy_from_slice(info);
    hkdf::expand::<H>(prk, &parts[..count], out)
}

/// The KEM's `suite_id`: "KEM" and its identifier.
fn kem_suite(kem_id: u16) -> [u8; 5] {
    let id = kem_id.to_be_bytes();
    [b'K', b'E', b'M', id[0], id[1]]
}

/// `ExtractAndExpand(dh, kem_context)` (RFC 9180 section 4.1), into
/// `out`, which is the KEM's `Nsecret`. The DH output is the caller's
/// to wipe.
fn extract_and_expand<H: Kdf>(
    kem_id: u16,
    dh: &[u8],
    enc: &[u8],
    recipient: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let suite = kem_suite(kem_id);
    let mut prk = labeled_extract::<H>(&suite, b"", b"eae_prk", dh);
    let result = labeled_expand::<H>(
        &suite,
        prk.as_ref(),
        b"shared_secret",
        &[enc, recipient],
        out,
    );
    prk.as_mut().zeroize();
    result
}

/// One side of an HPKE exchange after the key schedule: the AEAD
/// keyed, the nonce base, the message counter and the exporter
/// secret. Wiped on drop.
pub struct Context<H: Kdf, A: Cipher> {
    aead: A,
    // The vector suites read these two, to check the schedule.
    pub(crate) base_nonce: [u8; NONCE_SIZE],
    seq: u64,
    pub(crate) exporter: [u8; MAX_HASH],
    suite: [u8; 10],
    hash: PhantomData<fn() -> H>,
}

impl<H: Kdf, A: Cipher> Drop for Context<H, A> {
    fn drop(&mut self) {
        self.base_nonce.zeroize();
        self.exporter.zeroize();
    }
}

impl<H: Kdf, A: Cipher> Context<H, A> {
    /// `KeySchedule` (RFC 9180 section 5.1) in base mode: no PSK and
    /// no sender key, so the schedule is the shared secret and
    /// `info`.
    fn new(kem_id: u16, shared: &[u8], info: &[u8]) -> Result<Self, Error> {
        let mut suite = [0u8; 10];
        suite[..4].copy_from_slice(b"HPKE");
        suite[4..6].copy_from_slice(&kem_id.to_be_bytes());
        suite[6..8].copy_from_slice(&H::kdf_id().to_be_bytes());
        suite[8..].copy_from_slice(&A::aead_id().to_be_bytes());

        let psk_id_hash =
            labeled_extract::<H>(&suite, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract::<H>(&suite, b"", b"info_hash", info);
        // The mode, base, then the two hashes.
        let context: [&[u8]; 3] =
            [&[0x00], psk_id_hash.as_ref(), info_hash.as_ref()];
        let mut secret = labeled_extract::<H>(&suite, shared, b"secret", b"");

        let mut key = A::zero_key();
        let mut base_nonce = [0u8; NONCE_SIZE];
        let mut exporter = [0u8; MAX_HASH];
        let derived = labeled_expand::<H>(
            &suite,
            secret.as_ref(),
            b"key",
            &context,
            key.as_mut(),
        )
        .and_then(|()| {
            labeled_expand::<H>(
                &suite,
                secret.as_ref(),
                b"base_nonce",
                &context,
                &mut base_nonce,
            )
        })
        .and_then(|()| {
            labeled_expand::<H>(
                &suite,
                secret.as_ref(),
                b"exp",
                &context,
                &mut exporter[..size_of::<H::Output>()],
            )
        });
        secret.as_mut().zeroize();
        if let Err(e) = derived {
            base_nonce.zeroize();
            exporter.zeroize();
            return Err(e);
        }
        Ok(Context {
            aead: A::new(&key),
            base_nonce,
            seq: 0,
            exporter,
            suite,
            hash: PhantomData,
        })
    }

    /// The nonce for the next message: the base nonce with the
    /// message number XORed into its low bytes. RFC 9180 allows
    /// numbers to `2^96 - 1`; a `u64` runs out first, which no
    /// context will reach.
    pub(crate) fn nonce(&self) -> Result<[u8; NONCE_SIZE], Error> {
        if self.seq == u64::MAX {
            return Err(Error::SequenceExhausted);
        }
        let mut nonce = self.base_nonce;
        for (n, s) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        Ok(nonce)
    }

    /// Encrypts the next message in place and writes its tag
    /// (`ContextS.Seal`).
    pub fn encrypt(
        &mut self,
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; TAG_SIZE],
    ) -> Result<(), Error> {
        let nonce = self.nonce()?;
        self.aead.encrypt(&nonce, aad, data, tag)?;
        self.seq += 1;
        Ok(())
    }

    /// Checks and decrypts the next message in place
    /// (`ContextR.Open`). A message that does not authenticate is
    /// [`Error::AuthenticationFailed`], is wiped, and does not use up
    /// a number: the next call expects the same one.
    pub fn decrypt(
        &mut self,
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), Error> {
        let nonce = self.nonce()?;
        self.aead.decrypt(&nonce, aad, data, tag)?;
        self.seq += 1;
        Ok(())
    }

    /// Fills `out` with a secret derived from this context and
    /// `context` (`Context.Export`), the same on both sides. At most
    /// 255 digests, the bound HKDF sets.
    pub fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        labeled_expand::<H>(
            &self.suite,
            &self.exporter[..size_of::<H::Output>()],
            b"sec",
            &[context],
            out,
        )
    }
}

/// DHKEM over X25519, with HKDF-SHA256 (`kem_id` 0x0020).
pub mod x25519 {
    use super::{
        Cipher, Context, Kdf, extract_and_expand, labeled_expand,
        labeled_extract,
    };
    use crate::hash::sha2::Sha256;
    use crate::kex::x25519 as dh;
    use crate::{Error, Key, Random};
    use zeroize::Zeroize;

    const KEM_ID: u16 = 0x0020;

    /// The length of a private key, `Nsk`.
    pub const KEY_SIZE: usize = 32;

    /// The length of a public key, `Npk`.
    pub const PUBLIC_KEY_SIZE: usize = 32;

    /// The length of an encapsulation, `Nenc`.
    pub const ENCAPSULATED_SIZE: usize = 32;

    /// The length of the shared secret, `Nsecret`.
    const SECRET_SIZE: usize = 32;

    /// A recipient's private key.
    pub struct PrivateKey {
        key: dh::PrivateKey,
        public: PublicKey,
    }

    /// A recipient's public key.
    #[derive(Clone, Copy)]
    pub struct PublicKey {
        key: dh::PublicKey,
    }

    impl PrivateKey {
        fn from_dh(key: dh::PrivateKey) -> Self {
            let public = PublicKey {
                key: *key.public_key(),
            };
            PrivateKey { key, public }
        }

        /// A fresh key.
        pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
            Ok(Self::from_dh(dh::PrivateKey::generate(rng)?))
        }

        /// The key `DeriveKeyPair` makes from `ikm` (RFC 9180 section
        /// 7.1.3), which must hold at least [`KEY_SIZE`] bytes of
        /// entropy; shorter is [`Error::InvalidSeedLength`].
        pub fn from_seed(ikm: &[u8]) -> Result<Self, Error> {
            if ikm.len() < KEY_SIZE {
                return Err(Error::InvalidSeedLength(ikm.len()));
            }
            let suite = super::kem_suite(KEM_ID);
            let mut prk =
                labeled_extract::<Sha256>(&suite, b"", b"dkp_prk", ikm);
            let mut sk = Key::<[u8; KEY_SIZE]>::from([0u8; KEY_SIZE]);
            let expanded = labeled_expand::<Sha256>(
                &suite,
                prk.as_ref(),
                b"sk",
                &[],
                sk.as_mut(),
            );
            prk.zeroize();
            expanded?;
            Ok(Self::from_dh(dh::PrivateKey::new(&sk)))
        }

        /// A key from its serialized form, the 32 bytes of RFC 7748.
        pub fn new(secret: &Key<[u8; KEY_SIZE]>) -> Self {
            Self::from_dh(dh::PrivateKey::new(secret))
        }

        /// The serialized key. A secret, to be wiped.
        pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
            self.key.secret_bytes()
        }

        /// The public half.
        pub fn public_key(&self) -> &PublicKey {
            &self.public
        }

        /// The recipient's context for an encapsulation from a sender
        /// who used `info`. An encapsulation that gives the all-zero
        /// secret, from a low-order point, is
        /// [`Error::InvalidPublicKey`].
        pub fn recipient<H: Kdf, A: Cipher>(
            &self,
            enc: &[u8; ENCAPSULATED_SIZE],
            info: &[u8],
        ) -> Result<Context<H, A>, Error> {
            let mut dh = self.key.shared_secret(&dh::PublicKey::new(enc))?;
            let mut shared = [0u8; SECRET_SIZE];
            let result = extract_and_expand::<Sha256>(
                KEM_ID,
                &dh,
                enc,
                &self.public.bytes(),
                &mut shared,
            )
            .and_then(|()| Context::new(KEM_ID, &shared, info));
            dh.zeroize();
            shared.zeroize();
            result
        }
    }

    impl PublicKey {
        /// A key from its 32 bytes.
        pub fn new(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
            PublicKey {
                key: dh::PublicKey::new(bytes),
            }
        }

        /// The key's 32 bytes.
        pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
            self.key.bytes()
        }

        /// A fresh encapsulation to this key, and the sender's
        /// context for `info`. A low-order key, whose shared secret
        /// would be zero, is [`Error::InvalidPublicKey`].
        pub fn sender<H: Kdf, A: Cipher, R: Random>(
            &self,
            rng: &mut R,
            info: &[u8],
        ) -> Result<([u8; ENCAPSULATED_SIZE], Context<H, A>), Error> {
            self.sender_with(&PrivateKey::generate(rng)?, info)
        }

        /// As [`sender`](Self::sender), with the ephemeral key given:
        /// what the RFC's vectors fix.
        pub(crate) fn sender_with<H: Kdf, A: Cipher>(
            &self,
            ephemeral: &PrivateKey,
            info: &[u8],
        ) -> Result<([u8; ENCAPSULATED_SIZE], Context<H, A>), Error> {
            let enc = ephemeral.public.bytes();
            let mut dh = ephemeral.key.shared_secret(&self.key)?;
            let mut shared = [0u8; SECRET_SIZE];
            let result = extract_and_expand::<Sha256>(
                KEM_ID,
                &dh,
                &enc,
                &self.bytes(),
                &mut shared,
            )
            .and_then(|()| Context::new(KEM_ID, &shared, info));
            dh.zeroize();
            shared.zeroize();
            Ok((enc, result?))
        }
    }
}

/// DHKEM over a NIST curve. Keys are scalars of the curve's width,
/// public keys and encapsulations uncompressed points: compressed
/// ones are not the RFC 9180 serialization and are refused.
macro_rules! nist_kem {
    (
        $(#[$doc:meta])* $module:ident, $kem_id:literal, $hash:ident,
        $mask:literal
    ) => {
        $(#[$doc])*
        pub mod $module {
            use super::{
                Cipher, Context, Kdf, extract_and_expand, labeled_expand,
                labeled_extract,
            };
            use crate::hash::sha2::$hash;
            use crate::kex::ecdh::$module as dh;
            use crate::{Error, Random};
            use zeroize::Zeroize;

            const KEM_ID: u16 = $kem_id;

            /// The length of a private key, `Nsk`: the curve's width.
            pub const KEY_SIZE: usize = dh::KEY_SIZE;

            /// The length of a public key, `Npk`: an uncompressed
            /// point.
            pub const PUBLIC_KEY_SIZE: usize = dh::PUBLIC_KEY_SIZE;

            /// The length of an encapsulation, `Nenc`.
            pub const ENCAPSULATED_SIZE: usize = dh::PUBLIC_KEY_SIZE;

            /// The length of the shared secret, `Nsecret`: the KEM
            /// hash's digest.
            const SECRET_SIZE: usize =
                size_of::<<$hash as crate::hash::Hash>::Output>();

            /// A recipient's private key.
            pub struct PrivateKey {
                key: dh::PrivateKey,
                public: PublicKey,
            }

            /// A recipient's public key.
            #[derive(Clone, Copy)]
            pub struct PublicKey {
                key: dh::PublicKey,
            }

            impl PrivateKey {
                fn from_dh(key: dh::PrivateKey) -> Self {
                    let public = PublicKey {
                        key: *key.public_key(),
                    };
                    PrivateKey { key, public }
                }

                /// A fresh key.
                pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
                    Ok(Self::from_dh(dh::PrivateKey::generate(rng)?))
                }

                /// The key `DeriveKeyPair` makes from `ikm` (RFC 9180
                /// section 7.1.3), which must hold at least
                /// [`KEY_SIZE`] bytes of entropy; shorter is
                /// [`Error::InvalidSeedLength`]. Candidates are drawn
                /// until one is a valid scalar, which the first nearly
                /// always is; [`Error::KeyGenerationFailed`] after the
                /// RFC's 256.
                pub fn from_seed(ikm: &[u8]) -> Result<Self, Error> {
                    if ikm.len() < KEY_SIZE {
                        return Err(Error::InvalidSeedLength(ikm.len()));
                    }
                    let suite = super::kem_suite(KEM_ID);
                    let mut prk =
                        labeled_extract::<$hash>(&suite, b"", b"dkp_prk", ikm);
                    let mut candidate = [0u8; KEY_SIZE];
                    let mut found = Err(Error::KeyGenerationFailed);
                    for counter in 0..=255u8 {
                        if let Err(e) = labeled_expand::<$hash>(
                            &suite,
                            prk.as_ref(),
                            b"candidate",
                            &[&[counter]],
                            &mut candidate,
                        ) {
                            found = Err(e);
                            break;
                        }
                        // The bits past the order's, cleared.
                        candidate[0] &= $mask;
                        if let Ok(key) = dh::PrivateKey::try_new(&candidate) {
                            found = Ok(Self::from_dh(key));
                            break;
                        }
                    }
                    prk.as_mut().zeroize();
                    candidate.zeroize();
                    found
                }

                /// A key from its serialized form, the scalar
                /// big-endian; zero or at least the order is
                /// [`Error::InvalidPrivateKey`].
                pub fn try_new(secret: &[u8; KEY_SIZE]) -> Result<Self, Error> {
                    Ok(Self::from_dh(dh::PrivateKey::try_new(secret)?))
                }

                /// The serialized key. A secret, to be wiped.
                pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
                    self.key.secret_bytes()
                }

                /// The public half.
                pub fn public_key(&self) -> &PublicKey {
                    &self.public
                }

                /// The recipient's context for an encapsulation from
                /// a sender who used `info`. An encapsulation that is
                /// not an uncompressed point on the curve is
                /// [`Error::InvalidPublicKey`].
                pub fn recipient<H: Kdf, A: Cipher>(
                    &self,
                    enc: &[u8; ENCAPSULATED_SIZE],
                    info: &[u8],
                ) -> Result<Context<H, A>, Error> {
                    let ephemeral = PublicKey::try_new(enc)?;
                    let mut dh = self.key.shared_secret(&ephemeral.key);
                    let mut shared = [0u8; SECRET_SIZE];
                    let result = extract_and_expand::<$hash>(
                        KEM_ID,
                        &dh,
                        enc,
                        &self.public.bytes(),
                        &mut shared,
                    )
                    .and_then(|()| Context::new(KEM_ID, &shared, info));
                    dh.zeroize();
                    shared.zeroize();
                    result
                }
            }

            impl PublicKey {
                /// A key from its uncompressed point, checked to lie
                /// on the curve; anything else is
                /// [`Error::InvalidPublicKey`].
                pub fn try_new(
                    bytes: &[u8; PUBLIC_KEY_SIZE],
                ) -> Result<Self, Error> {
                    if bytes[0] != 0x04 {
                        return Err(Error::InvalidPublicKey);
                    }
                    Ok(PublicKey {
                        key: dh::PublicKey::try_from_sec1(bytes)?,
                    })
                }

                /// The uncompressed point.
                pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
                    self.key.sec1_bytes()
                }

                /// A fresh encapsulation to this key, and the
                /// sender's context for `info`.
                pub fn sender<H: Kdf, A: Cipher, R: Random>(
                    &self,
                    rng: &mut R,
                    info: &[u8],
                ) -> Result<([u8; ENCAPSULATED_SIZE], Context<H, A>), Error> {
                    self.sender_with(&PrivateKey::generate(rng)?, info)
                }

                /// As [`sender`](Self::sender), with the ephemeral
                /// key given: what the RFC's vectors fix.
                pub(crate) fn sender_with<H: Kdf, A: Cipher>(
                    &self,
                    ephemeral: &PrivateKey,
                    info: &[u8],
                ) -> Result<([u8; ENCAPSULATED_SIZE], Context<H, A>), Error> {
                    let enc = ephemeral.public.bytes();
                    let mut dh = ephemeral.key.shared_secret(&self.key);
                    let mut shared = [0u8; SECRET_SIZE];
                    let result = extract_and_expand::<$hash>(
                        KEM_ID,
                        &dh,
                        &enc,
                        &self.bytes(),
                        &mut shared,
                    )
                    .and_then(|()| Context::new(KEM_ID, &shared, info));
                    dh.zeroize();
                    shared.zeroize();
                    Ok((enc, result?))
                }
            }
        }
    };
}

nist_kem!(
    /// DHKEM over P-256, with HKDF-SHA256 (`kem_id` 0x0010).
    p256, 0x0010, Sha256, 0xff
);
nist_kem!(
    /// DHKEM over P-384, with HKDF-SHA384 (`kem_id` 0x0011).
    p384, 0x0011, Sha384, 0xff
);
nist_kem!(
    /// DHKEM over P-521, with HKDF-SHA512 (`kem_id` 0x0012). A
    /// candidate key's top byte keeps one bit: the order is 521 bits.
    p521, 0x0012, Sha512, 0x01
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::CtrDrbg;

    /// Every KEM with every KDF and AEAD round-trips, including
    /// P-384 and SHA-384, which the CFRG's vectors do not cover.
    #[test]
    fn every_suite_round_trips() {
        macro_rules! suite {
            ($kem:ident, $h:ty, $a:ty) => {{
                let mut rng = CtrDrbg::from_system().unwrap();
                let key = $kem::PrivateKey::generate(&mut rng).unwrap();
                let (enc, mut s) = key
                    .public_key()
                    .sender::<$h, $a, _>(&mut rng, b"info")
                    .unwrap();
                let mut r = key.recipient::<$h, $a>(&enc, b"info").unwrap();
                for message in [&b"first"[..], b"", b"third"] {
                    let mut data = message.to_vec();
                    let mut tag = [0u8; TAG_SIZE];
                    s.encrypt(b"aad", &mut data, &mut tag).unwrap();
                    r.decrypt(b"aad", &mut data, &tag).unwrap();
                    assert_eq!(data, message);
                }
                let (mut a, mut b) = ([0u8; 40], [0u8; 40]);
                s.export(b"ctx", &mut a).unwrap();
                r.export(b"ctx", &mut b).unwrap();
                assert_eq!(a, b);
            }};
        }
        macro_rules! kem {
            ($kem:ident) => {
                suite!($kem, Sha256, Gcm<Aes128>);
                suite!($kem, Sha384, Gcm<Aes256>);
                suite!($kem, Sha512, ChaCha20Poly1305);
            };
        }
        kem!(x25519);
        kem!(p256);
        kem!(p384);
        kem!(p521);
    }

    /// A different `info`, a tampered message, or one out of order
    /// fails; a failure does not use up the message's number.
    #[test]
    fn mismatches_fail() {
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = p384::PrivateKey::generate(&mut rng).unwrap();
        let (enc, mut s) = key
            .public_key()
            .sender::<Sha384, Gcm<Aes256>, _>(&mut rng, b"info")
            .unwrap();
        let mut wrong =
            key.recipient::<Sha384, Gcm<Aes256>>(&enc, b"infO").unwrap();
        let mut r =
            key.recipient::<Sha384, Gcm<Aes256>>(&enc, b"info").unwrap();

        let mut tags = [[0u8; TAG_SIZE]; 2];
        let mut first = *b"one";
        let mut second = *b"two";
        s.encrypt(b"", &mut first, &mut tags[0]).unwrap();
        s.encrypt(b"", &mut second, &mut tags[1]).unwrap();

        let mut copy = first;
        assert_eq!(
            wrong.decrypt(b"", &mut copy, &tags[0]),
            Err(Error::AuthenticationFailed)
        );
        // The second message first: refused, and wiped.
        let mut copy = second;
        assert!(r.decrypt(b"", &mut copy, &tags[1]).is_err());
        assert_eq!(copy, [0u8; 3]);
        // The first still opens, then the second.
        r.decrypt(b"", &mut first, &tags[0]).unwrap();
        r.decrypt(b"", &mut second, &tags[1]).unwrap();
        assert_eq!((&first, &second), (b"one", b"two"));
    }

    /// Encapsulations and keys HPKE does not allow are refused.
    #[test]
    fn bad_keys_are_refused() {
        // A compressed point is not RFC 9180's serialization.
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = p256::PrivateKey::generate(&mut rng).unwrap();
        let mut point = key.public_key().bytes();
        point[0] = 0x02;
        assert_eq!(
            p256::PublicKey::try_new(&point).err(),
            Some(Error::InvalidPublicKey)
        );
        assert!(key.recipient::<Sha256, Gcm<Aes128>>(&point, b"").is_err());
        // An X25519 encapsulation of the low-order point zero, whose
        // shared secret is zero.
        let key = x25519::PrivateKey::generate(&mut rng).unwrap();
        assert_eq!(
            key.recipient::<Sha256, Gcm<Aes128>>(&[0; 32], b"").err(),
            Some(Error::InvalidPublicKey)
        );
        // Seeds shorter than a key.
        assert_eq!(
            x25519::PrivateKey::from_seed(&[1; 31]).err(),
            Some(Error::InvalidSeedLength(31))
        );
        assert_eq!(
            p521::PrivateKey::from_seed(&[1; 65]).err(),
            Some(Error::InvalidSeedLength(65))
        );
        // A scalar at zero.
        assert!(p384::PrivateKey::try_new(&[0; 48]).is_err());
    }

    /// The counter's last value is refused rather than wrapped, and
    /// an export past HKDF's bound is refused.
    #[test]
    fn limits() {
        let mut rng = CtrDrbg::from_system().unwrap();
        let key = x25519::PrivateKey::generate(&mut rng).unwrap();
        let (_, mut s) = key
            .public_key()
            .sender::<Sha256, ChaCha20Poly1305, _>(&mut rng, b"")
            .unwrap();
        s.seq = u64::MAX - 1;
        let mut tag = [0u8; TAG_SIZE];
        s.encrypt(b"", &mut [], &mut tag).unwrap();
        assert_eq!(
            s.encrypt(b"", &mut [], &mut tag),
            Err(Error::SequenceExhausted)
        );
        let mut out = std::vec![0u8; 255 * 32 + 1];
        assert!(s.export(b"", &mut out).is_err());
        assert!(s.export(b"", &mut out[..255 * 32]).is_ok());
    }
}
