//! ECDSA (FIPS 186-5) over the NIST prime curves P-256, P-384 and
//! P-521.
//!
//! A key is a secret scalar `d` and the public point `Q = d G`. A
//! signature is a pair `(r, s)` made from a fresh nonce `k` and the
//! message's digest, and checked by recovering `k G` from the pair
//! and the public key. Each curve is a module of its own, [`p256`],
//! [`p384`] and [`p521`], with the same two key types and the same
//! calls; P-256 with SHA-256 is the pairing everything speaks,
//! P-384 with SHA-384 the one for a higher security level, and
//! P-521 with SHA-512 the one certificates at the top of a chain
//! sometimes carry.
//!
//! ECDSA is what certificates, TLS and most signed formats outside
//! the SSH and Signal families ask for by name. Where nothing does,
//! [`ed25519`](crate::sig::ed25519) is simpler and faster, and its
//! keys are a quarter the size.
//!
//! # Nonces
//!
//! The nonce is derived, by RFC 6979, from the key and the digest
//! through HMAC over the signature's own hash, so signing consumes
//! no randomness and the same key and message always give the same
//! signature. A random nonce is where ECDSA has failed in practice:
//! one repeated nonce, or a few biased bits of one, and the key is
//! recovered from the signatures. There is no random-nonce path.
//!
//! # Signature forms
//!
//! [`sign`](p256::PrivateKey::sign) returns `r || s` at fixed width,
//! the IEEE P1363 form that JWS and COSE carry. X.509, TLS and CMS
//! carry the DER `ECDSA-Sig-Value` instead;
//! [`signature_der`](p256::signature_der) and
//! [`signature_from_der`](p256::signature_from_der) convert.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::random::CtrDrbg;
//! use scytale::sig::ecdsa::p256::{PrivateKey, PublicKey};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::generate(&mut rng)?;
//! let signature = key.sign::<Sha256>(b"the message")?;
//!
//! // The public key travels as SEC 1 bytes, or as DER or PEM.
//! let public = PublicKey::try_from_sec1(&key.public_key().sec1_bytes())?;
//! public.verify::<Sha256>(b"the message", &signature)?;
//! assert!(public.verify::<Sha256>(b"another", &signature).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! Signing is a fixed sequence of field operations for a given
//! curve: the base point is multiplied by the complete formulas,
//! which have no case analysis, the scalar is consumed in fixed
//! windows with the table scanned whole, and inversions are
//! exponentiations. Verification handles only public values, and
//! takes the faster path whose work depends on them: one pass over
//! both scalars in signed digits, adding only where a digit is
//! nonzero.

use crate::BlockType;
use crate::hash::Hash;

macro_rules! ecdsa_curve {
    (
        $constants:expr, $limbs:literal, $curve:literal,
        $der:literal, $public_der:literal
    ) => {
        crate::math::ec::key_types!(
            $constants, $limbs, $curve, "signing",
            der $der, public der $public_der
        );

        /// The length of a signature, `r || s`.
        pub const SIGNATURE_SIZE: usize = 2 * KEY_SIZE;

        impl PrivateKey {
            /// Signs `message` under `H`, with the nonce RFC 6979
            /// derives from the key and the digest: the same inputs
            /// always give the same signature.
            ///
            /// `H` is the hash the verifier will use; P-256 pairs
            /// with SHA-256, P-384 with SHA-384 and P-521 with
            /// SHA-512 almost everywhere, though any hash is
            /// accepted.
            pub fn sign<H: Hash + Clone + BlockType + Default>(
                &self,
                message: &[u8],
            ) -> Result<[u8; SIGNATURE_SIZE], Error> {
                let e = Engine::new(&$constants);
                let mut out = [0u8; SIGNATURE_SIZE];
                self.secret.sign::<H>(&e, message, &mut out)?;
                Ok(out)
            }
        }

        impl PublicKey {
            /// Checks that `signature` signs `message` under `H`.
            ///
            /// [`Error::InvalidSignature`] for anything that does
            /// not, which deliberately says no more than that.
            pub fn verify<H: Hash + Default>(
                &self,
                message: &[u8],
                signature: &[u8; SIGNATURE_SIZE],
            ) -> Result<(), Error> {
                let e = Engine::new(&$constants);
                self.point.verify::<H>(&e, message, signature)
            }
        }

        /// A signature as the DER `ECDSA-Sig-Value` of RFC 5480,
        /// written into the front of `out`, returning the length,
        /// which varies with the values' leading bits;
        /// `SIGNATURE_SIZE + 8` always suffices.
        pub fn signature_der(
            signature: &[u8; SIGNATURE_SIZE],
            out: &mut [u8],
        ) -> Result<usize, Error> {
            crate::math::ec::signature_to_der(signature, out)
        }

        /// The `r || s` form of a DER `ECDSA-Sig-Value`. Anything
        /// that is not exactly that structure, at most the curve's
        /// width per integer, is [`Error::InvalidEncoding`].
        pub fn signature_from_der(
            der: &[u8],
        ) -> Result<[u8; SIGNATURE_SIZE], Error> {
            let mut out = [0u8; SIGNATURE_SIZE];
            crate::math::ec::signature_from_der(der, &mut out)?;
            Ok(out)
        }
    };
}

/// ECDSA over P-256, the curve of nearly every deployment.
pub mod p256 {
    use super::*;
    ecdsa_curve!(crate::math::ec::P256, 4, "P-256", 138, 91);
}

/// ECDSA over P-384, for the higher security level.
pub mod p384 {
    use super::*;
    ecdsa_curve!(crate::math::ec::P384, 6, "P-384", 185, 120);
}

/// ECDSA over P-521, whose scalars are 66 bytes: 521 bits, with
/// seven to spare in the top byte.
pub mod p521 {
    use super::*;
    ecdsa_curve!(crate::math::ec::P521, 9, "P-521", 241, 158);
}

#[cfg(test)]
mod tests {
    use super::p256;
    use super::p384;
    use super::p521;
    use crate::Error;
    use crate::hash::sha2::{Sha256, Sha384, Sha512};

    fn unhex<'a>(hex: &str, buf: &'a mut [u8]) -> &'a [u8] {
        let hex = hex.as_bytes();
        for (byte, pair) in buf.iter_mut().zip(hex.chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        &buf[..hex.len() / 2]
    }

    /// What OpenSSL 3.5 writes for a fresh P-256 key, from
    /// `openssl genpkey -algorithm EC -pkeyopt
    /// ec_paramgen_curve:prime256v1` and `openssl pkey`, with and
    /// without `-pubout`; the `EC PRIVATE KEY` block from
    /// `openssl ec`; and `openssl dgst -sha256 -sign` over
    /// "the message".
    const P256_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgB/aOoz3xdXpnb+Lo\n\
        CU2H3nmI++86daKltGQhtGxvZx2hRANCAASBCk2N7Q+ISt+ES+2Y41DC8Mda5nLA\n\
        pWG6nFqW9J5Xjltl1H7ZhXux5qvmVTkhr97/ckCgUuHfO9Kqc5hs9EPl\n\
        -----END PRIVATE KEY-----\n";
    const P256_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgQpNje0PiErfhEvtmONQwvDHWuZy\n\
        wKVhupxalvSeV45bZdR+2YV7sear5lU5Ia/e/3JAoFLh3zvSqnOYbPRD5Q==\n\
        -----END PUBLIC KEY-----\n";
    const P256_SEC1_PEM: &[u8] = b"-----BEGIN EC PRIVATE KEY-----\n\
        MHcCAQEEIAf2jqM98XV6Z2/i6AlNh955iPvvOnWipbRkIbRsb2cdoAoGCCqGSM49\n\
        AwEHoUQDQgAEgQpNje0PiErfhEvtmONQwvDHWuZywKVhupxalvSeV45bZdR+2YV7\n\
        sear5lU5Ia/e/3JAoFLh3zvSqnOYbPRD5Q==\n\
        -----END EC PRIVATE KEY-----\n";
    const P256_SECRET: &str =
        "07f68ea33df1757a676fe2e8094d87de7988fbef3a75a2a5b46421b46c6f671d";
    const P256_SIGNATURE_DER: &str = "\
         30440220062f924d2ae58a58efc01e2df5aeb87d884c1568d590c9f3d527dd48\
         f0f3dc7902205b7ca9329a561b30afd7fc115d654a26184f16b82c1ef60cfbf5\
         1c9d0ad2280f";

    /// The same for P-384, `secp384r1`.
    const P384_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAkn/Ab8LDrB+RK7sFT\n\
        veTOEd9tQGlDyNvfPQ5KOtrKnq2O46ujkvaKYE9ZN+pWKTehZANiAASEy/kmxI/w\n\
        0WBK1aXV1RLN5Mt8jOMG01gBX6fIEafO6mqDsi5iuuDX2iGfW93nxml/kzh0wmvg\n\
        e/9s48bT2T4bbGreFb9rdHQHAZA5bQEGMa6J7sF1U1WuVTspVDJOjpk=\n\
        -----END PRIVATE KEY-----\n";
    const P384_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\n\
        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhMv5JsSP8NFgStWl1dUSzeTLfIzjBtNY\n\
        AV+nyBGnzupqg7IuYrrg19ohn1vd58Zpf5M4dMJr4Hv/bOPG09k+G2xq3hW/a3R0\n\
        BwGQOW0BBjGuie7BdVNVrlU7KVQyTo6Z\n\
        -----END PUBLIC KEY-----\n";
    const P384_SIGNATURE_DER: &str = "\
         306402300bc7023f1082d37078ef30b86b20701896a653b185204bc9e127c5fd\
         1797629b2f76fb0d83a17b84b1120a82291a762802305275911bc84a2b0dd15c\
         339414ce5a032fa12c368da5b6d13a5c0111b3a4b0dc2268bac6d63ad46cfe8c\
         b75c6ede83f5";

    /// The same for P-521, `secp521r1`, signed with SHA-512.
    const P521_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBscOuQmb2XIhMPMvD\n\
        ySuGD34HGNMLgN11mMupKH4hIJTtadhZ/BCmn4fgMAXJ3l9fQWz0ubM1j9hFrRQa\n\
        0B4qDB2hgYkDgYYABAElRz/ToG0jMV69FivXABsxyuXgFFA+XYuLfGz80QqP440C\n\
        i2PzoMxWj03BfESZasgcos0BB3qVApbQazO2wpBWDAGk6PGH9lvuZmSokOV7te9M\n\
        fbtSH3kXfPJCAsnfI0QLtUBsRKqQUBTFmvWalQ7XqzfsJfS+kAjKKTkFHz8JcByn\n\
        Pg==\n\
        -----END PRIVATE KEY-----\n";
    const P521_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\n\
        MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBJUc/06BtIzFevRYr1wAbMcrl4BRQ\n\
        Pl2Li3xs/NEKj+ONAotj86DMVo9NwXxEmWrIHKLNAQd6lQKW0GsztsKQVgwBpOjx\n\
        h/Zb7mZkqJDle7XvTH27Uh95F3zyQgLJ3yNEC7VAbESqkFAUxZr1mpUO16s37CX0\n\
        vpAIyik5BR8/CXAcpz4=\n\
        -----END PUBLIC KEY-----\n";
    const P521_SEC1_PEM: &[u8] = b"-----BEGIN EC PRIVATE KEY-----\n\
        MIHcAgEBBEIBscOuQmb2XIhMPMvDySuGD34HGNMLgN11mMupKH4hIJTtadhZ/BCm\n\
        n4fgMAXJ3l9fQWz0ubM1j9hFrRQa0B4qDB2gBwYFK4EEACOhgYkDgYYABAElRz/T\n\
        oG0jMV69FivXABsxyuXgFFA+XYuLfGz80QqP440Ci2PzoMxWj03BfESZasgcos0B\n\
        B3qVApbQazO2wpBWDAGk6PGH9lvuZmSokOV7te9MfbtSH3kXfPJCAsnfI0QLtUBs\n\
        RKqQUBTFmvWalQ7XqzfsJfS+kAjKKTkFHz8JcBynPg==\n\
        -----END EC PRIVATE KEY-----\n";
    const P521_SECRET: &str = "\
         01b1c3ae4266f65c884c3ccbc3c92b860f7e0718d30b80dd7598cba9287e2120\
         94ed69d859fc10a69f87e03005c9de5f5f416cf4b9b3358fd845ad141ad01e2a\
         0c1d";
    const P521_SIGNATURE_DER: &str = "\
         308188024200fbc2840c7db593eb6c697cb08b13ccdb076c9a4f3cf3f902e59e\
         4ce14fa2179fe007149dfd87d915c1d758884d2ce251af5d1efd3d7e77ded4d9\
         f6e6c177e4a97b024200b8cda2097e466693caeebbf8d95870a8ee8d3135b7c8\
         9a7190ae4a080180af3c305effd0c9e9742c1a06a0686adc3ba18b76596d8924\
         975694b284367861f3bf5f";

    #[test]
    fn openssl_p256() {
        let key = p256::PrivateKey::try_from_pem(P256_PEM).unwrap();
        let mut buf = [0u8; 32];
        assert_eq!(key.secret_bytes()[..], *unhex(P256_SECRET, &mut buf));
        let public = p256::PublicKey::try_from_pem(P256_PUBLIC_PEM).unwrap();
        assert_eq!(public.sec1_bytes(), key.public_key().sec1_bytes());
        let sec1 = p256::PrivateKey::try_from_pem(P256_SEC1_PEM).unwrap();
        assert_eq!(sec1.secret_bytes(), key.secret_bytes());

        // The bare ECPrivateKey DER loads directly; its parameters
        // name P-256, so P-384 refuses it, and a PKCS#8 structure
        // is not an ECPrivateKey at all.
        let mut der = [0u8; 512];
        let (_, n) =
            crate::codec::pem::decode(P256_SEC1_PEM, &mut der).unwrap();
        let sec1 = p256::PrivateKey::try_from_sec1_der(&der[..n]).unwrap();
        assert_eq!(sec1.secret_bytes(), key.secret_bytes());
        assert_eq!(sec1.public_key().sec1_bytes(), public.sec1_bytes());
        assert!(matches!(
            p384::PrivateKey::try_from_sec1_der(&der[..n]),
            Err(Error::WrongAlgorithm)
        ));
        let (_, n) = crate::codec::pem::decode(P256_PEM, &mut der).unwrap();
        assert!(matches!(
            p256::PrivateKey::try_from_sec1_der(&der[..n]),
            Err(Error::InvalidEncoding)
        ));

        // Written back byte for byte, with the sizes the constants
        // promise.
        let mut out = [0u8; 512];
        let n = key.pem_bytes(&mut out).unwrap();
        assert_eq!(&out[..n], P256_PEM);
        assert_eq!(n, p256::PEM_SIZE);
        let n = public.pem_bytes(&mut out).unwrap();
        assert_eq!(&out[..n], P256_PUBLIC_PEM);
        assert_eq!(n, p256::PUBLIC_KEY_PEM_SIZE);
        let n = key.der_bytes(&mut out).unwrap();
        assert_eq!(n, p256::DER_SIZE);
        assert_eq!(
            p256::PrivateKey::try_from_der(&out[..n])
                .unwrap()
                .secret_bytes(),
            key.secret_bytes()
        );
        let n = public.der_bytes(&mut out).unwrap();
        assert_eq!(n, p256::PUBLIC_KEY_DER_SIZE);
        assert_eq!(
            p256::PublicKey::try_from_der(&out[..n])
                .unwrap()
                .sec1_bytes(),
            public.sec1_bytes()
        );

        // OpenSSL's signature verifies, through the DER conversion,
        // and converts back to the same DER.
        let mut der = [0u8; 80];
        let der = unhex(P256_SIGNATURE_DER, &mut der);
        let signature = p256::signature_from_der(der).unwrap();
        public.verify::<Sha256>(b"the message", &signature).unwrap();
        let n = p256::signature_der(&signature, &mut out).unwrap();
        assert_eq!(&out[..n], der);
        assert!(public.verify::<Sha256>(b"the messagf", &signature).is_err());
        assert!(public.verify::<Sha384>(b"the message", &signature).is_err());
    }

    #[test]
    fn openssl_p384() {
        let key = p384::PrivateKey::try_from_pem(P384_PEM).unwrap();
        let public = p384::PublicKey::try_from_pem(P384_PUBLIC_PEM).unwrap();
        assert_eq!(public.sec1_bytes(), key.public_key().sec1_bytes());
        let mut out = [0u8; 512];
        assert_eq!(key.pem_bytes(&mut out), Ok(p384::PEM_SIZE));
        assert_eq!(&out[..p384::PEM_SIZE], P384_PEM);
        assert_eq!(public.pem_bytes(&mut out), Ok(p384::PUBLIC_KEY_PEM_SIZE));
        assert_eq!(&out[..p384::PUBLIC_KEY_PEM_SIZE], P384_PUBLIC_PEM);
        assert_eq!(key.der_bytes(&mut out), Ok(p384::DER_SIZE));
        assert_eq!(public.der_bytes(&mut out), Ok(p384::PUBLIC_KEY_DER_SIZE));

        let mut der = [0u8; 112];
        let der = unhex(P384_SIGNATURE_DER, &mut der);
        let signature = p384::signature_from_der(der).unwrap();
        // Signed with SHA-256 despite the curve; any hash goes.
        public.verify::<Sha256>(b"the message", &signature).unwrap();
        let n = p384::signature_der(&signature, &mut out).unwrap();
        assert_eq!(&out[..n], der);
    }

    #[test]
    fn openssl_p521() {
        let key = p521::PrivateKey::try_from_pem(P521_PEM).unwrap();
        let mut buf = [0u8; 66];
        assert_eq!(key.secret_bytes()[..], *unhex(P521_SECRET, &mut buf));
        let public = p521::PublicKey::try_from_pem(P521_PUBLIC_PEM).unwrap();
        assert_eq!(public.sec1_bytes(), key.public_key().sec1_bytes());
        let sec1 = p521::PrivateKey::try_from_pem(P521_SEC1_PEM).unwrap();
        assert_eq!(sec1.secret_bytes(), key.secret_bytes());
        let mut out = [0u8; 512];
        assert_eq!(key.pem_bytes(&mut out), Ok(p521::PEM_SIZE));
        assert_eq!(&out[..p521::PEM_SIZE], P521_PEM);
        assert_eq!(public.pem_bytes(&mut out), Ok(p521::PUBLIC_KEY_PEM_SIZE));
        assert_eq!(&out[..p521::PUBLIC_KEY_PEM_SIZE], P521_PUBLIC_PEM);
        assert_eq!(key.der_bytes(&mut out), Ok(p521::DER_SIZE));
        assert_eq!(public.der_bytes(&mut out), Ok(p521::PUBLIC_KEY_DER_SIZE));

        let mut der = [0u8; 160];
        let der = unhex(P521_SIGNATURE_DER, &mut der);
        let signature = p521::signature_from_der(der).unwrap();
        public.verify::<Sha512>(b"the message", &signature).unwrap();
        let n = p521::signature_der(&signature, &mut out).unwrap();
        assert_eq!(&out[..n], der);
        assert!(public.verify::<Sha512>(b"the messagf", &signature).is_err());
        assert!(public.verify::<Sha384>(b"the message", &signature).is_err());

        // Our own signatures verify, and are deterministic.
        let ours = key.sign::<Sha512>(b"the message").unwrap();
        public.verify::<Sha512>(b"the message", &ours).unwrap();
        assert_eq!(ours, key.sign::<Sha512>(b"the message").unwrap());
        assert_eq!(p521::SIGNATURE_SIZE, 132);
    }

    /// The form is reported, and a public point that is not the
    /// secret's own is refused as a pair that disagrees.
    #[test]
    fn a_carried_point_is_reported_and_checked() {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let a = p256::PrivateKey::generate(&mut rng).unwrap();
        let b = p256::PrivateKey::generate(&mut rng).unwrap();
        let mut der = [0u8; p256::DER_SIZE];
        let n = a.der_bytes(&mut der).unwrap();
        let (back, form) =
            p256::PrivateKey::try_from_der_with_form(&der[..n]).unwrap();
        assert_eq!(back.public_key().sec1_bytes(), a.public_key().sec1_bytes());
        assert_eq!(
            form,
            crate::Pkcs8Form {
                v1: false,
                public_key: true
            }
        );
        // The point is the last thing written; swap in another key's.
        let point = &mut der[n - p256::PUBLIC_KEY_SIZE..n];
        assert_eq!(point, &a.public_key().sec1_bytes());
        point.copy_from_slice(&b.public_key().sec1_bytes());
        assert_eq!(
            p256::PrivateKey::try_from_der(&der[..n]).err(),
            Some(Error::InconsistentKey)
        );
    }

    /// A key of the other curve is refused by every importer.
    #[test]
    fn curves_do_not_mix() {
        assert_eq!(
            p256::PrivateKey::try_from_pem(P384_PEM).err(),
            Some(Error::WrongAlgorithm)
        );
        assert_eq!(
            p384::PrivateKey::try_from_pem(P256_PEM).err(),
            Some(Error::WrongAlgorithm)
        );
        assert_eq!(
            p256::PublicKey::try_from_pem(P384_PUBLIC_PEM).err(),
            Some(Error::WrongAlgorithm)
        );
        assert_eq!(
            p384::PrivateKey::try_from_pem(P256_SEC1_PEM).err(),
            Some(Error::WrongAlgorithm)
        );
        let mut der = [0u8; 112];
        let der = unhex(P384_SIGNATURE_DER, &mut der);
        assert_eq!(
            p256::signature_from_der(der).err(),
            Some(Error::InvalidEncoding)
        );
    }

    /// Generated keys round trip through every form and sign
    /// deterministically.
    #[test]
    fn round_trips() {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let key = p384::PrivateKey::generate(&mut rng).unwrap();
        let again = p384::PrivateKey::try_new(&key.secret_bytes()).unwrap();
        assert_eq!(
            again.public_key().sec1_bytes(),
            key.public_key().sec1_bytes()
        );
        let sig = key.sign::<Sha384>(b"x").unwrap();
        assert_eq!(again.sign::<Sha384>(b"x").unwrap(), sig);
        let mut out = [0u8; 512];
        let n = key.der_bytes(&mut out).unwrap();
        let back = p384::PrivateKey::try_from_der(&out[..n]).unwrap();
        assert_eq!(back.secret_bytes(), key.secret_bytes());
        let n = key.pem_bytes(&mut out).unwrap();
        let back = p384::PrivateKey::try_from_pem(&out[..n]).unwrap();
        assert_eq!(back.secret_bytes(), key.secret_bytes());
        back.public_key().verify::<Sha384>(b"x", &sig).unwrap();

        // The DER signature form: a leading zero and a top bit each
        // change the length, so several signatures go through.
        for i in 0..8u8 {
            let sig = key.sign::<Sha384>(&[i]).unwrap();
            let n = p384::signature_der(&sig, &mut out).unwrap();
            assert!(n <= p384::SIGNATURE_SIZE + 8);
            assert_eq!(p384::signature_from_der(&out[..n]), Ok(sig));
        }
        assert_eq!(
            p384::signature_der(&sig, &mut [])
                .err()
                .map(|e| matches!(e, Error::OutputTooSmall(_))),
            Some(true)
        );
        assert_eq!(
            p256::PrivateKey::try_new(&[0u8; 32]).err(),
            Some(Error::InvalidPrivateKey)
        );
    }
}
