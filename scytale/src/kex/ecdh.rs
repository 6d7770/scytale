//! ECDH (SP 800-56A) over the NIST prime curves P-256, P-384 and
//! P-521.
//!
//! Each party keeps a secret scalar and publishes the point it makes
//! from the base point; multiplying the other's point by one's own
//! scalar lands both on the same point, whose x-coordinate is the
//! shared secret. Each curve is a module of its own, [`p256`],
//! [`p384`] and [`p521`], with the same two key types and the same
//! calls.
//!
//! This is the agreement TLS, IKE and most standards-track
//! protocols name; where nothing names a curve,
//! [`x25519`](crate::kex::x25519) does the same job with less to
//! get wrong. The shared secret is a curve coordinate, not a
//! uniform string: feed it to [`hkdf`](crate::kdf::hkdf) to make
//! keys, never use it as one.
//!
//! # Invalid curve points
//!
//! A peer who sends a point that is not on the curve can learn the
//! secret scalar a few bits at a time, since the arithmetic then
//! runs in a group of the attacker's choosing. Every [`PublicKey`]
//! here is checked to lie on the curve when it is constructed, so
//! no such point reaches [`shared_secret`]; the curves have prime
//! order, so there are no small subgroups to check for besides.
//!
//! [`PublicKey`]: p256::PublicKey
//! [`shared_secret`]: p256::PrivateKey::shared_secret
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::hkdf;
//! use scytale::kex::ecdh::p256::PrivateKey;
//! use scytale::random::CtrDrbg;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let alice = PrivateKey::generate(&mut rng)?;
//! let bob = PrivateKey::generate(&mut rng)?;
//!
//! // Each side needs only the other's public key.
//! let shared = alice.shared_secret(bob.public_key());
//! assert_eq!(shared, bob.shared_secret(alice.public_key()));
//! let mut key = [0u8; 32];
//! hkdf::derive::<Sha256>(b"", &shared, &[b"session v1"], &mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! The scalar multiplication is a fixed sequence of field
//! operations for a given curve: fixed windows, a table scanned
//! whole, and the cases the Jacobian addition does not cover settled
//! by masks rather than branches; SECURITY.md sets out which cases
//! those are.

macro_rules! ecdh_curve {
    (
        $constants:expr, $limbs:literal, $curve:literal,
        $der:literal, $public_der:literal
    ) => {
        crate::math::ec::key_types!(
            $constants, $limbs, $curve, "key agreement",
            der $der, public der $public_der
        );

        impl PrivateKey {
            /// The secret shared with the holder of `public`: the
            /// x-coordinate of the product of the two keys, big-endian.
            ///
            /// The point was checked when `public` was made and the
            /// scalar when the private key was, so there is nothing
            /// left for this call to refuse.
            pub fn shared_secret(&self, public: &PublicKey) -> [u8; KEY_SIZE] {
                let e = Engine::new(&$constants);
                let mut out = [0u8; KEY_SIZE];
                self.secret.shared_secret(&e, &public.point, &mut out);
                out
            }
        }
    };
}

/// ECDH over P-256.
pub mod p256 {
    ecdh_curve!(crate::math::ec::P256, 4, "P-256", 138, 91);
}

/// ECDH over P-384.
pub mod p384 {
    ecdh_curve!(crate::math::ec::P384, 6, "P-384", 185, 120);
}

/// ECDH over P-521, whose coordinates are 66 bytes: 521 bits, with
/// seven to spare in the top byte.
pub mod p521 {
    ecdh_curve!(crate::math::ec::P521, 9, "P-521", 241, 158);
}

#[cfg(test)]
mod tests {
    use super::{p256, p384, p521};
    use crate::Error;

    fn unhex<'a>(hex: &str, buf: &'a mut [u8]) -> &'a [u8] {
        let hex = hex.as_bytes();
        for (byte, pair) in buf.iter_mut().zip(hex.chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        &buf[..hex.len() / 2]
    }

    /// Wycheproof's first ECDH case on P-256: a private scalar, the
    /// peer's SubjectPublicKeyInfo, and the shared secret.
    #[test]
    fn wycheproof_normal_case() {
        let mut buf = [0u8; 32];
        let private: [u8; 32] = unhex(
            "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
            &mut buf,
        )
        .try_into()
        .unwrap();
        let mut buf = [0u8; 91];
        let peer = unhex(
            "3059301306072a8648ce3d020106082a8648ce3d0301070342000462d5bd3372\
             af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9\
             e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
            &mut buf,
        );
        let mut buf = [0u8; 32];
        let shared = unhex(
            "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285",
            &mut buf,
        );
        let key = p256::PrivateKey::try_new(&private).unwrap();
        let peer = p256::PublicKey::try_from_der(peer).unwrap();
        assert_eq!(key.shared_secret(&peer)[..], shared[..]);
    }

    /// A P-521 agreement OpenSSL 3.5 made: `openssl pkeyutl
    /// -derive` between a key and a peer's public key, both from
    /// `openssl genpkey -algorithm EC -pkeyopt
    /// ec_paramgen_curve:secp521r1`.
    #[test]
    fn openssl_p521() {
        let mut buf = [0u8; 66];
        let private: [u8; 66] = unhex(
            "01b1c3ae4266f65c884c3ccbc3c92b860f7e0718d30b80dd7598cba9287e2120\
             94ed69d859fc10a69f87e03005c9de5f5f416cf4b9b3358fd845ad141ad01e2a\
             0c1d",
            &mut buf,
        )
        .try_into()
        .unwrap();
        const PEER_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\n\
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBlaUyC0BX3nuEVcmhhFseZUX9DIgG\n\
            wd8Nfq28Ls5eIsVc2qcRR+N7yjkPs9cG3TKkZ+Omxw8hzohU0s58eIGT8i4Bs6AT\n\
            rsn5ElivMWf6t2o0c+jdZlyabKH4F5WWe6kg1CMFc2wZaQdaNqgQxxBV6a+miN56\n\
            zPj+Mgwe0NlVE/fMD14=\n\
            -----END PUBLIC KEY-----\n";
        let mut buf = [0u8; 66];
        let shared = unhex(
            "01ad92837df80129ec07377ee76493944cddcd8ccc47e58678fa23bb7b04fd4a\
             704d2accdbe2b7feec54172c0923823e6786123222f1da7ca79869e97db5e854\
             a3b2",
            &mut buf,
        );
        let key = p521::PrivateKey::try_new(&private).unwrap();
        let peer = p521::PublicKey::try_from_pem(PEER_PEM).unwrap();
        assert_eq!(key.shared_secret(&peer)[..], shared[..]);
    }

    /// Every curve agrees from either side, through every public
    /// key form.
    #[test]
    fn agreement_through_formats() {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let a = p384::PrivateKey::generate(&mut rng).unwrap();
        let b = p384::PrivateKey::generate(&mut rng).unwrap();
        let shared = a.shared_secret(b.public_key());
        let mut out = [0u8; 512];
        let n = b.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(n, p384::PUBLIC_KEY_DER_SIZE);
        let via_der = p384::PublicKey::try_from_der(&out[..n]).unwrap();
        assert_eq!(a.shared_secret(&via_der), shared);
        let n = b.public_key().pem_bytes(&mut out).unwrap();
        let via_pem = p384::PublicKey::try_from_pem(&out[..n]).unwrap();
        assert_eq!(a.shared_secret(&via_pem), shared);
        let n = a.der_bytes(&mut out).unwrap();
        assert_eq!(n, p384::DER_SIZE);
        let a2 = p384::PrivateKey::try_from_der(&out[..n]).unwrap();
        assert_eq!(b.shared_secret(a2.public_key()), shared);

        // The same round trip on P-521, whose encodings carry a
        // 66-byte scalar and 133-byte point.
        let a = p521::PrivateKey::generate(&mut rng).unwrap();
        let b = p521::PrivateKey::generate(&mut rng).unwrap();
        let shared = a.shared_secret(b.public_key());
        let n = b.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(n, p521::PUBLIC_KEY_DER_SIZE);
        let via_der = p521::PublicKey::try_from_der(&out[..n]).unwrap();
        assert_eq!(a.shared_secret(&via_der), shared);
        let n = a.der_bytes(&mut out).unwrap();
        assert_eq!(n, p521::DER_SIZE);
        let a2 = p521::PrivateKey::try_from_der(&out[..n]).unwrap();
        assert_eq!(b.shared_secret(a2.public_key()), shared);
        assert_eq!(p521::PUBLIC_KEY_SIZE, 133);
        assert_eq!(p521::KEY_SIZE, 66);

        // A P-256 point is not a P-384 key, however presented.
        let c = p256::PrivateKey::generate(&mut rng).unwrap();
        let n = c.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(
            p384::PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::WrongAlgorithm)
        );
        assert_eq!(
            p384::PublicKey::try_from_sec1(&c.public_key().sec1_bytes()).err(),
            Some(Error::InvalidPublicKey)
        );
    }
}
