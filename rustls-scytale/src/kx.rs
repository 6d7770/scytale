//! Key exchange: X25519, the NIST curves, ML-KEM, and the hybrids of
//! the two that TLS 1.3 now prefers.

use alloc::boxed::Box;
use alloc::vec::Vec;

use rustls::Error;
use rustls::crypto::kx::{
    ActiveKeyExchange, CompletedKeyExchange, Hybrid, HybridLayout, NamedGroup,
    SharedSecret, StartedKeyExchange, SupportedKxGroup,
};
use rustls::error::PeerMisbehaved;
use scytale::kem::ml_kem;
use scytale::kex::{ecdh, x25519};
use zeroize::Zeroize;

use crate::random::generator;

/// X25519 (RFC 7748).
pub static X25519: &dyn SupportedKxGroup = &X25519Group;

/// ECDH over P-256, `secp256r1`.
pub static SECP256R1: &dyn SupportedKxGroup = &P256Group;

/// ECDH over P-384, `secp384r1`.
pub static SECP384R1: &dyn SupportedKxGroup = &P384Group;

/// ML-KEM-768 alone (FIPS 203).
pub static MLKEM768: &dyn SupportedKxGroup = &MlKem768Group;

/// ML-KEM-1024 alone (FIPS 203).
pub static MLKEM1024: &dyn SupportedKxGroup = &MlKem1024Group;

/// X25519 and ML-KEM-768 together: secure if either is.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: HybridLayout {
        classical_share_len: x25519::KEY_SIZE,
        post_quantum_client_share_len: ml_kem::ml_kem_768::PUBLIC_KEY_SIZE,
        post_quantum_server_share_len: ml_kem::ml_kem_768::CIPHERTEXT_SIZE,
        post_quantum_first: true,
    },
};

/// P-256 and ML-KEM-768 together.
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: SECP256R1,
    post_quantum: MLKEM768,
    name: NamedGroup::secp256r1MLKEM768,
    layout: HybridLayout {
        classical_share_len: ecdh::p256::PUBLIC_KEY_SIZE,
        post_quantum_client_share_len: ml_kem::ml_kem_768::PUBLIC_KEY_SIZE,
        post_quantum_server_share_len: ml_kem::ml_kem_768::CIPHERTEXT_SIZE,
        post_quantum_first: false,
    },
};

/// P-384 and ML-KEM-1024 together: the hybrid at the strength CNSA
/// 2.0 asks for. Its client share is about 1.7 KB, so it is not a
/// default; the classical part comes first, as for P-256.
pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &Hybrid {
    classical: SECP384R1,
    post_quantum: MLKEM1024,
    name: NamedGroup::secp384r1MLKEM1024,
    layout: HybridLayout {
        classical_share_len: ecdh::p384::PUBLIC_KEY_SIZE,
        post_quantum_client_share_len: ml_kem::ml_kem_1024::PUBLIC_KEY_SIZE,
        post_quantum_server_share_len: ml_kem::ml_kem_1024::CIPHERTEXT_SIZE,
        post_quantum_first: false,
    },
};

fn invalid_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

/// A shared secret handed to rustls, the bare array it came in
/// wiped.
fn shared<const N: usize>(mut secret: [u8; N]) -> SharedSecret {
    let out = SharedSecret::from(&secret[..]);
    secret.zeroize();
    out
}

#[derive(Debug)]
struct X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let mut rng = generator().map_err(|_| Error::FailedToGetRandomBytes)?;
        let key = x25519::PrivateKey::generate(&mut rng)
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        let public = key.public_key().bytes();
        Ok(StartedKeyExchange::Single(Box::new(X25519Active {
            key,
            public,
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Active {
    key: x25519::PrivateKey,
    public: [u8; x25519::KEY_SIZE],
}

impl ActiveKeyExchange for X25519Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: &[u8; x25519::KEY_SIZE] =
            peer.try_into().map_err(|_| invalid_share())?;
        // A low-order point gives the all-zero secret, which scytale
        // refuses (RFC 7748 section 6.1, RFC 8446 section 7.4.2).
        let secret = self
            .key
            .shared_secret(&x25519::PublicKey::new(peer))
            .map_err(|_| invalid_share())?;
        Ok(shared(secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// ECDH over one of the NIST curves. Shares are uncompressed points,
/// the only form TLS 1.3 allows (RFC 8446 section 4.2.8.2), so a
/// compressed one, which scytale would read, is refused here.
macro_rules! ecdh_group {
    ($group:ident, $active:ident, $curve:ident, $name:ident) => {
        #[derive(Debug)]
        struct $group;

        impl SupportedKxGroup for $group {
            fn start(&self) -> Result<StartedKeyExchange, Error> {
                let mut rng =
                    generator().map_err(|_| Error::FailedToGetRandomBytes)?;
                let key = ecdh::$curve::PrivateKey::generate(&mut rng)
                    .map_err(|_| Error::FailedToGetRandomBytes)?;
                let public = key.public_key().sec1_bytes();
                Ok(StartedKeyExchange::Single(Box::new($active {
                    key,
                    public,
                })))
            }

            fn name(&self) -> NamedGroup {
                NamedGroup::$name
            }
        }

        struct $active {
            key: ecdh::$curve::PrivateKey,
            public: [u8; ecdh::$curve::PUBLIC_KEY_SIZE],
        }

        impl ActiveKeyExchange for $active {
            fn complete(
                self: Box<Self>,
                peer: &[u8],
            ) -> Result<SharedSecret, Error> {
                if peer.len() != ecdh::$curve::PUBLIC_KEY_SIZE
                    || peer.first() != Some(&0x04)
                {
                    return Err(invalid_share());
                }
                // Checked to lie on the curve; there is no other way
                // to make a public key.
                let peer = ecdh::$curve::PublicKey::try_from_sec1(peer)
                    .map_err(|_| invalid_share())?;
                Ok(shared(self.key.shared_secret(&peer)))
            }

            fn pub_key(&self) -> &[u8] {
                &self.public
            }

            fn group(&self) -> NamedGroup {
                NamedGroup::$name
            }
        }
    };
}

ecdh_group!(P256Group, P256Active, p256, secp256r1);
ecdh_group!(P384Group, P384Active, p384, secp384r1);

/// ML-KEM as a key exchange (draft-ietf-tls-mlkem): the client's
/// share is an encapsulation key and the server's a ciphertext to it.
/// The server has nothing to start before it has the client's share,
/// so it does both halves at once.
macro_rules! ml_kem_group {
    ($group:ident, $active:ident, $set:ident, $name:ident) => {
        #[derive(Debug)]
        struct $group;

        impl SupportedKxGroup for $group {
            fn start(&self) -> Result<StartedKeyExchange, Error> {
                let mut rng =
                    generator().map_err(|_| Error::FailedToGetRandomBytes)?;
                let key = ml_kem::$set::PrivateKey::generate(&mut rng)
                    .map_err(|_| Error::FailedToGetRandomBytes)?;
                let public = key.public_key().bytes().to_vec();
                // Boxed: the expanded key is kilobytes, and it waits
                // for the server's reply.
                Ok(StartedKeyExchange::Single(Box::new($active {
                    key: Box::new(key),
                    public,
                })))
            }

            fn start_and_complete(
                &self,
                client_share: &[u8],
            ) -> Result<CompletedKeyExchange, Error> {
                let share: &[u8; ml_kem::$set::PUBLIC_KEY_SIZE] =
                    client_share.try_into().map_err(|_| invalid_share())?;
                // FIPS 203's input check: every coefficient reduced.
                let public = ml_kem::$set::PublicKey::try_new(share)
                    .map_err(|_| invalid_share())?;
                let mut rng =
                    generator().map_err(|_| Error::FailedToGetRandomBytes)?;
                let (ciphertext, secret) = public
                    .encapsulate(&mut rng)
                    .map_err(|_| Error::FailedToGetRandomBytes)?;
                Ok(CompletedKeyExchange {
                    group: NamedGroup::$name,
                    pub_key: ciphertext.to_vec(),
                    secret: shared(secret),
                })
            }

            fn name(&self) -> NamedGroup {
                NamedGroup::$name
            }
        }

        struct $active {
            key: Box<ml_kem::$set::PrivateKey>,
            public: Vec<u8>,
        }

        impl ActiveKeyExchange for $active {
            fn complete(
                self: Box<Self>,
                ciphertext: &[u8],
            ) -> Result<SharedSecret, Error> {
                let ciphertext: &[u8; ml_kem::$set::CIPHERTEXT_SIZE] =
                    ciphertext.try_into().map_err(|_| invalid_share())?;
                // Never fails: a ciphertext not made for this key gives
                // a secret the sender does not have (implicit
                // rejection), and the handshake fails at Finished.
                Ok(shared(self.key.decapsulate(ciphertext)))
            }

            fn pub_key(&self) -> &[u8] {
                &self.public
            }

            fn group(&self) -> NamedGroup {
                NamedGroup::$name
            }
        }
    };
}

ml_kem_group!(MlKem768Group, MlKem768Active, ml_kem_768, MLKEM768);
ml_kem_group!(MlKem1024Group, MlKem1024Active, ml_kem_1024, MLKEM1024);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Every group agrees with itself, client to server, and the
    /// server's share completes the client's exchange.
    #[test]
    fn every_group_agrees() {
        for group in [
            X25519,
            SECP256R1,
            SECP384R1,
            MLKEM768,
            MLKEM1024,
            X25519MLKEM768,
            SECP256R1MLKEM768,
            SECP384R1MLKEM1024,
        ] {
            let client = group.start().unwrap().into_single();
            assert_eq!(client.group(), group.name());
            let server = group.start_and_complete(client.pub_key()).unwrap();
            assert_eq!(server.group, group.name());
            let secret = client.complete(&server.pub_key).unwrap();
            assert_eq!(
                secret.secret_bytes(),
                server.secret.secret_bytes(),
                "{:?}",
                group.name()
            );
        }
    }

    /// Shares of the wrong length or form are the peer's fault.
    #[test]
    fn bad_shares_are_refused() {
        let invalid = |r: Result<SharedSecret, Error>| {
            matches!(
                r,
                Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
            )
        };
        for group in [X25519, SECP256R1, SECP384R1, MLKEM768, MLKEM1024] {
            let client = group.start().unwrap().into_single();
            assert!(invalid(client.complete(&[1, 2, 3])), "{:?}", group.name());
        }
        // The low-order point zero, for X25519.
        let client = X25519.start().unwrap().into_single();
        assert!(invalid(client.complete(&[0; 32])));
        // A compressed P-256 point, which is a valid point but not a
        // valid TLS share.
        let peer = SECP256R1.start().unwrap().into_single();
        let mut compressed = vec![0x02 | (peer.pub_key()[64] & 1)];
        compressed.extend_from_slice(&peer.pub_key()[1..33]);
        compressed.resize(65, 0);
        let client = SECP256R1.start().unwrap().into_single();
        assert!(invalid(client.complete(&compressed)));
        // A point off the curve.
        let mut off = peer.pub_key().to_vec();
        off[64] ^= 1;
        let client = SECP256R1.start().unwrap().into_single();
        assert!(invalid(client.complete(&off)));
        // An ML-KEM encapsulation key whose coefficients are not
        // reduced: all ones.
        assert!(matches!(
            MLKEM768.start_and_complete(&[0xff; 1184]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));
        // A hybrid share one byte short.
        let client = X25519MLKEM768.start().unwrap().into_single();
        let short = &client.pub_key()[1..];
        assert!(X25519MLKEM768.start_and_complete(short).is_err());
    }

    /// The hybrids put the post-quantum part where the draft says:
    /// first for X25519MLKEM768, second for the NIST curves.
    #[test]
    fn hybrid_share_layout() {
        let client = X25519MLKEM768.start().unwrap().into_single();
        assert_eq!(client.pub_key().len(), 1184 + 32);
        let client = SECP256R1MLKEM768.start().unwrap().into_single();
        assert_eq!(client.pub_key().len(), 65 + 1184);
        assert_eq!(client.pub_key()[0], 0x04);
        let client = SECP384R1MLKEM1024.start().unwrap().into_single();
        assert_eq!(client.pub_key().len(), 97 + 1568);
        assert_eq!(client.pub_key()[0], 0x04);
        let server = SECP384R1MLKEM1024
            .start_and_complete(client.pub_key())
            .unwrap();
        assert_eq!(server.pub_key.len(), 97 + 1568);
    }
}
