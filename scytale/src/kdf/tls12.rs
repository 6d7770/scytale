//! The TLS 1.2 PRF (RFC 5246 section 5): `P_hash` under HMAC, which
//! turns a secret, a label and a seed into as much keying material as
//! the handshake needs.
//!
//! TLS 1.2 derives its master secret from the premaster secret and
//! its key block from the master secret with this one function; TLS
//! 1.3 replaced it with HKDF. It is here for the protocol
//! implementations that still speak 1.2, and for nothing else: a new
//! design wants [`hkdf`](crate::kdf::hkdf).
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::kdf::tls12;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let premaster = [0x5a; 48];
//! let client_random = [0x01; 32];
//! let server_random = [0x02; 32];
//!
//! // The master secret, then the key block from it; the seed is the
//! // two randoms, in the order each derivation names.
//! let mut master = [0u8; 48];
//! tls12::prf::<Sha256>(
//!     &premaster,
//!     b"master secret",
//!     &[&client_random, &server_random],
//!     &mut master,
//! )?;
//! let mut key_block = [0u8; 104];
//! tls12::prf::<Sha256>(
//!     &master,
//!     b"key expansion",
//!     &[&server_random, &client_random],
//!     &mut key_block,
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! The hash is the cipher suite's: SHA-256 for every suite RFC 5246
//! defines, SHA-384 for the ones that name it. The extended master
//! secret of RFC 7627 is the same call with the label `"extended
//! master secret"` and the session hash as the seed.

use crate::hash::Hash;
use crate::mac::Mac;
use crate::mac::hmac::Hmac;
use crate::{BlockType, Error};
use zeroize::Zeroize;

/// Fills `out` with `PRF(secret, label, seed)`.
///
/// `seed` is a list of parts, joined in the order given, so the two
/// randoms or a label and a hash need no buffer to put them in.
///
/// Returns [`Error::InvalidLength`] for an empty `label` or `out`:
/// the function is defined on neither, and a caller that asks for
/// nothing has lost track of what it is deriving.
pub fn prf<H: Hash + Clone + BlockType + Default>(
    secret: &[u8],
    label: &[u8],
    seed: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    if label.is_empty() || out.is_empty() {
        return Err(Error::InvalidLength(out.len()));
    }
    // A(0) = label || seed; A(i) = HMAC(secret, A(i-1)); and the
    // output is HMAC(secret, A(i) || label || seed) for i from 1.
    // Each `finalize` leaves the MAC keyed and ready for the next.
    let mut mac = Hmac::<H>::new(secret);
    mac.update(label);
    for part in seed {
        mac.update(part);
    }
    let mut a = mac.finalize();
    for chunk in out.chunks_mut(size_of::<H::Output>()) {
        mac.update(a.as_ref());
        mac.update(label);
        for part in seed {
            mac.update(part);
        }
        let p = mac.finalize();
        chunk.copy_from_slice(&p.as_ref()[..chunk.len()]);
        mac.update(a.as_ref());
        a = mac.finalize();
    }
    // The last A is one HMAC away from output the caller holds; it
    // does not linger here.
    a.as_mut().zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::{Sha256, Sha384, Sha512};

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// The vectors the TLS working group circulated for the 1.2 PRF
    /// (IETF mail archive, fzVCzk-z3FShgGJ6DOXqM1ydxms): a 16-byte
    /// secret, the label "test label", a 16-byte seed, and 100 bytes
    /// of output under SHA-256.
    #[test]
    fn ietf_sha256_vector() {
        let secret = hex::<16>("9bbe436ba940f017b17652849a71db35");
        let seed = hex::<16>("a0ba9f936cda311827a6f796ffd5198c");
        let mut out = [0u8; 100];
        prf::<Sha256>(&secret, b"test label", &[&seed], &mut out).unwrap();
        let want = hex::<100>(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a\
             6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab\
             4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701\
             87347b66",
        );
        assert_eq!(out, want);
    }

    /// The same for SHA-384 (148 bytes) and SHA-512 (196 bytes).
    #[test]
    fn ietf_sha384_and_sha512_vectors() {
        let secret = hex::<16>("b80b733d6ceefcdc71566ea48e5567df");
        let seed = hex::<16>("cd665cf6a8447dd6ff8b27555edb7465");
        let mut out = [0u8; 148];
        prf::<Sha384>(&secret, b"test label", &[&seed], &mut out).unwrap();
        let want = hex::<148>(
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd\
             e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd\
             8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425\
             9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6\
             91c8f3a26854308d5eaa3be85e0990703d73e56f",
        );
        assert_eq!(out[..], want[..]);

        let secret = hex::<16>("b0323523c1853599584d88568bbb05eb");
        let seed = hex::<16>("d4640e12e4bcdbfb437f03e6ae418ee5");
        let mut out = [0u8; 196];
        prf::<Sha512>(&secret, b"test label", &[&seed], &mut out).unwrap();
        let want = hex::<196>(
            "1261f588c798c5c201ff036e7a9cb5edcd7fe3f94c669a122a4638d7d508b283\
             042df6789875c7147e906d868bc75c45e20eb40c1cf4a1713b27371f68432592\
             f7dc8ea8ef223e12ea8507841311bf68653d0cfc4056d811f025c45ddfa6e6fe\
             c702f054b409d6f28dd0a3233e498da41a3e75c5630eedbe22fe254e33a1b0e9\
             f6b9826675bec7d01a845658dc9c397545401d40b9f46c7a400ee1b8f81ca0a6\
             0d1a397a1028bff5d2ef5066126842fb8da4197632bdb54ff6633f86bbc836e6\
             40d4d898",
        );
        assert_eq!(out[..], want[..]);
    }

    /// The seed may come in parts, and the output in any length.
    #[test]
    fn seed_parts_join_and_lengths_vary() {
        let secret = [7u8; 32];
        let mut whole = [0u8; 70];
        prf::<Sha256>(&secret, b"l", &[b"abcdef"], &mut whole).unwrap();
        let mut parts = [0u8; 70];
        prf::<Sha256>(&secret, b"l", &[b"ab", b"", b"cdef"], &mut parts)
            .unwrap();
        assert_eq!(whole, parts);
        // A prefix of the output is the same whatever the length asked.
        let mut short = [0u8; 33];
        prf::<Sha256>(&secret, b"l", &[b"abcdef"], &mut short).unwrap();
        assert_eq!(short[..], whole[..33]);
    }

    #[test]
    fn empty_label_or_output_is_refused() {
        let mut out = [0u8; 8];
        assert_eq!(
            prf::<Sha256>(&[1], b"", &[b"s"], &mut out),
            Err(Error::InvalidLength(8))
        );
        assert_eq!(
            prf::<Sha256>(&[1], b"l", &[b"s"], &mut []),
            Err(Error::InvalidLength(0))
        );
    }
}
