//! NIST ACVP vector suites, and the Wycheproof suites for what ACVP
//! does not cover.
//!
//! Inside the crate rather than in `tests/`, because an integration
//! test is a separate crate and would see only the public types,
//! while an implementation is validated in its own right. Test names
//! read `acvp::primitive::implementation::suite`. Implementations
//! that do not exist on this architecture are left out rather than
//! named and skipped; [`inventory`] prints the ones that do and says
//! which of them this processor can run.
//!
//! An implementation is validated by the suite for the primitive it
//! implements, at every key size: AES by `aes_ecb`, each hash by its
//! own suites. What is built on top of a primitive is tested once,
//! on the implementation the processor picks, since a mode, a MAC or
//! a KDF does not vary with the code underneath it.

#[allow(unused_imports)]
use std::{eprintln, format, println, string::String, vec, vec::Vec};

mod support;

use support::acvp::{
    aes_cbc as cbc, aes_ccm as ccm, aes_cfb1 as cfb1, aes_cfb8 as cfb8,
    aes_cfb128 as cfb128, aes_ctr as ctr, aes_ecb as ecb, aes_ff1 as ff1,
    aes_ff3_1 as ff3_1, aes_gcm as gcm, aes_gcm_siv as gcm_siv,
    aes_gmac as gmac, aes_kw as kw, aes_kwp as kwp, aes_ofb as ofb,
    aes_xpn as xpn, aes_xts as xts, cmac_aes as cmac, cshake as cshake_vectors,
    ctr_drbg as drbg, hmac as hmac_vectors, kmac as kmac_vectors,
    pbkdf as pbkdf_vectors, sha as sha_vectors, shake as shake_vectors,
};

/// Defines the suites for an implementation that is always
/// available. `both` covers suites with a Monte Carlo test as well as
/// a one-shot one; `aft_only` those with just the one-shot test.
macro_rules! suites {
    ($name:ident, $ty:ty, $suite:ident, both) => {
        mod $name {
            use super::*;

            #[test]
            fn acvp_aft() {
                $suite::run_aft::<$ty>();
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                $suite::run_mct::<$ty>();
            }
        }
    };
    ($name:ident, $ty:ty, $suite:ident, aft_only) => {
        mod $name {
            use super::*;

            #[test]
            fn acvp_aft() {
                $suite::run_aft::<$ty>();
            }
        }
    };
}

/// As `hardware_suites!`, for a block cipher, which says whether the
/// processor can run it rather than failing to be built.
#[cfg_attr(
    not(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )),
    allow(unused_macros)
)]
macro_rules! cipher_hardware_suites {
    ($name:ident, $ty:ty, $suite:ident, $what:literal, $kind:ident) => {
        mod $name {
            use super::*;

            /// Whether to run, reporting a skip when the processor
            /// cannot. A silent skip would look like a pass.
            fn supported() -> bool {
                if <$ty>::supported() {
                    return true;
                }
                eprintln!(concat!($what, " not available; skipping"));
                false
            }

            hardware_tests!($ty, $suite, $kind);
        }
    };
}

/// Defines the suites for a hardware implementation, which skip when
/// the processor lacks the instructions. Only the hashes use it: an
/// architecture with no hardware hash never expands it.
#[allow(unused_macros)]
macro_rules! hardware_suites {
    ($name:ident, $ty:ty, $suite:ident, $what:literal, $kind:ident) => {
        mod $name {
            use super::*;
            use crate::Error;

            /// Whether to run, reporting a skip when the processor
            /// cannot. A silent skip would look like a pass.
            fn supported() -> bool {
                match <$ty>::try_new(&<$ty as crate::KeyType>::zero_key()) {
                    Ok(_) => true,
                    Err(Error::NotSupported) => {
                        eprintln!(concat!($what, " not available; skipping"));
                        false
                    }
                    Err(e) => panic!("{e}"),
                }
            }

            hardware_tests!($ty, $suite, $kind);
        }
    };
}

/// The test bodies inside a hardware implementation's module.
#[cfg_attr(
    not(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )),
    allow(unused_macros)
)]
macro_rules! hardware_tests {
    ($ty:ty, $suite:ident, both) => {
        #[test]
        fn acvp_aft() {
            if supported() {
                $suite::run_aft::<$ty>();
            }
        }

        /// Slow; run with `cargo test-extended`.
        #[test]
        #[ignore]
        fn acvp_mct() {
            if supported() {
                $suite::run_mct::<$ty>();
            }
        }
    };
    ($ty:ty, $suite:ident, aft_only) => {
        #[test]
        fn acvp_aft() {
            if supported() {
                $suite::run_aft::<$ty>();
            }
        }
    };
}

/// Defines the suites for one implementation at each of the three
/// key widths, which are three types.
macro_rules! widths {
    ($n128:ident, $n192:ident, $n256:ident, $($p:ident)::+,
     $suite:ident, $kind:ident) => {
        suites!($n128, $($p)::+<16>, $suite, $kind);
        suites!($n192, $($p)::+<24>, $suite, $kind);
        suites!($n256, $($p)::+<32>, $suite, $kind);
    };
}

/// As `widths!`, for a hardware implementation.
#[cfg_attr(
    not(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )),
    allow(unused_macros)
)]
macro_rules! hardware_widths {
    ($n128:ident, $n192:ident, $n256:ident, $($p:ident)::+,
     $suite:ident, $what:literal, $kind:ident) => {
        cipher_hardware_suites!($n128, $($p)::+<16>, $suite, $what, $kind);
        cipher_hardware_suites!($n192, $($p)::+<24>, $suite, $what, $kind);
        cipher_hardware_suites!($n256, $($p)::+<32>, $suite, $what, $kind);
    };
}

/// Runs one mode's suite against the dispatching AES, at every key
/// width. A mode built out of the cipher's own operations does not
/// vary with the implementation beneath it, and `aes_ecb` validates
/// each implementation in turn against the vectors for it; running
/// the mode on the dispatched cipher covers the selector as well, and
/// takes the fastest code the processor has. Suites with a Monte
/// Carlo test take no second argument.
///
/// A mode that is written out for the processor rather than built out
/// of the cipher is a different matter: there the mode is the
/// implementation, and which one runs depends on the machine. Those
/// suites run every implementation the processor has, one after
/// another, so that none goes unvalidated for want of the right
/// hardware under the test. See `aes_ctr` and `aes_gcm`.
macro_rules! modes {
    ($suite:ident) => {
        modes!($suite, both);
    };
    ($suite:ident, $kind:ident) => {
        use super::*;
        use crate::cipher::aes;

        widths!(
            automatic_128,
            automatic_192,
            automatic_256,
            aes::Aes,
            $suite,
            $kind
        );
    };
}

/// Runs one suite against every AES implementation this architecture
/// has, at every key width. Used by `aes_ecb`, which is where an
/// implementation is validated: its one-shot cases drive whole
/// buffers through `encrypt_blocks` and `decrypt_blocks`, and its
/// Monte Carlo cases chain 600,000 single-block calls.
macro_rules! every_aes {
    ($suite:ident) => {
        every_aes!($suite, both);
    };
    ($suite:ident, $kind:ident) => {
        use super::*;
        use crate::cipher::aes;

        // The dispatching type is not here. On any one processor it
        // is one of the implementations below, so its cases are theirs
        // run twice -- and a Monte Carlo run is 600,000 chained calls
        // a width. What it alone covers is the dispatch, and
        // `aes::tests::matches_ttable` covers that against the
        // table-driven code at every width, both directions, a block
        // at a time and in bulk.
        widths!(
            bitsliced_128,
            bitsliced_192,
            bitsliced_256,
            aes::portable::bitsliced::Aes,
            $suite,
            $kind
        );
        widths!(
            ttable_128,
            ttable_192,
            ttable_256,
            aes::portable::ttable::Aes,
            $suite,
            $kind
        );

        #[cfg(target_arch = "x86_64")]
        hardware_widths!(
            aesni_128,
            aesni_192,
            aesni_256,
            aes::x86_64::aesni::Aes,
            $suite,
            "AES-NI",
            $kind
        );

        #[cfg(target_arch = "x86_64")]
        hardware_widths!(
            vaes_128,
            vaes_192,
            vaes_256,
            aes::x86_64::vaes::Aes,
            $suite,
            "VAES",
            $kind
        );

        #[cfg(target_arch = "aarch64")]
        hardware_widths!(
            armv8_128,
            armv8_192,
            armv8_256,
            aes::aarch64::armv8::Aes,
            $suite,
            "ARMv8 AES",
            $kind
        );

        #[cfg(target_arch = "riscv64")]
        hardware_widths!(
            zkn_128,
            zkn_192,
            zkn_256,
            aes::riscv64::zkn::Aes,
            $suite,
            "RISC-V scalar AES",
            $kind
        );

        #[cfg(target_arch = "riscv64")]
        hardware_widths!(
            zvkned_128,
            zvkned_192,
            zvkned_256,
            aes::riscv64::zvkned::Aes,
            $suite,
            "RISC-V vector AES",
            $kind
        );
    };
}

/// AES (FIPS 197) with each block encrypted independently, and so
/// the suite that validates each implementation of the cipher.
mod aes_ecb {
    every_aes!(ecb);
}

/// AES in cipher block chaining mode (SP 800-38A).
mod aes_cbc {
    modes!(cbc);
}

/// AES in cipher feedback mode with full-block segments.
mod aes_cfb128 {
    modes!(cfb128);
}

/// AES in cipher feedback mode with 8-bit segments.
mod aes_cfb8 {
    modes!(cfb8);
}

/// AES in cipher feedback mode with 1-bit segments.
mod aes_cfb1 {
    modes!(cfb1);
}

/// AES in output feedback mode (SP 800-38A).
mod aes_ofb {
    modes!(ofb);
}

/// AES in counter mode (SP 800-38A). This suite has no Monte Carlo
/// test.
mod aes_ctr {
    modes!(ctr, aft_only);
}

/// AES in Galois/Counter Mode (SP 800-38D), the first authenticated
/// mode. This suite has no Monte Carlo test.
mod aes_gcm {
    modes!(gcm, aft_only);
}

/// AES in counter with CBC-MAC mode (SP 800-38C). This suite has no
/// Monte Carlo test.
mod aes_ccm {
    modes!(ccm, aft_only);
}

/// AES-GCM-SIV (RFC 8452), which survives a repeated nonce.
///
/// Two widths rather than three: RFC 8452 derives its keys for
/// 16- and 32-byte keys only, so AES-192 is not a cipher this mode
/// is defined over, and the type system refuses it.
mod aes_gcm_siv {
    use super::*;
    use crate::cipher::aes;

    suites!(automatic_128, aes::Aes<16>, gcm_siv, aft_only);
    suites!(automatic_256, aes::Aes<32>, gcm_siv, aft_only);
}

/// ACVP-AES-GMAC: GCM with no plaintext, which is how the crate
/// offers GMAC.
mod aes_gmac {
    modes!(gmac, aft_only);
}

/// AES in XTS mode (SP 800-38E), the mode used for storage.
mod aes_xts {
    modes!(xts, aft_only);
}

/// AES-FF1, format-preserving encryption (SP 800-38G).
mod aes_ff1 {
    modes!(ff1, aft_only);
}

/// AES-FF3-1, format-preserving encryption (SP 800-38G revision 1).
mod aes_ff3_1 {
    modes!(ff3_1, aft_only);
}

/// AES-GCM with extended packet numbering, as MACsec uses it.
mod aes_xpn {
    modes!(xpn, aft_only);
}

/// AES key wrapping without padding (SP 800-38F). Deterministic and
/// nonce-free, and the only mode here whose output is longer than its
/// input. This suite has no Monte Carlo test.
mod aes_kw {
    modes!(kw, aft_only);
}

/// AES key wrapping with padding (SP 800-38F), which takes any length
/// from one byte up. This suite has no Monte Carlo test.
mod aes_kwp {
    modes!(kwp, aft_only);
}

/// CMAC over AES (SP 800-38B), the MAC built from the cipher. This
/// suite has no Monte Carlo test.
mod cmac_aes {
    modes!(cmac, aft_only);
}

/// The CTR_DRBG random number generator (SP 800-90A). Not generic
/// over a block cipher: it is AES-256 by construction, so there is
/// one run rather than one per implementation.
mod ctr_drbg {
    use super::*;

    #[test]
    fn acvp_aft() {
        drbg::run_aft();
    }
}

/// Defines the SHA-2 suites for one implementation of one variant.
/// The hardware ones skip, saying so, when the processor cannot.
macro_rules! sha2_suites {
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal,
     $family:expr) => {
        sha2_suites!($name, $ty, $file, $algorithm, $family, "portable code");
    };
    ($name:ident, $ty:ty, $file:literal, $algorithm:literal,
     $family:expr, $what:literal) => {
        mod $name {
            use super::*;
            use crate::Error;

            /// Whether to run, reporting a skip when the processor
            /// cannot. A silent skip would look like a pass.
            fn supported() -> bool {
                match <$ty>::try_new() {
                    Ok(_) => true,
                    Err(Error::NotSupported) => {
                        eprintln!(concat!($what, " not available; skipping"));
                        false
                    }
                    Err(e) => panic!("{e}"),
                }
            }

            #[test]
            fn acvp_aft() {
                if supported() {
                    sha_vectors::run_aft($file, $algorithm, $family, || {
                        <$ty>::try_new().expect("supported")
                    });
                }
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                if supported() {
                    sha_vectors::run_mct($file, $algorithm, $family, || {
                        <$ty>::try_new().expect("supported")
                    });
                }
            }
        }
    };
}

/// Runs one SHA-2 variant's suites against each implementation this
/// architecture has. The dispatching type is not among them: it is
/// one of these at run time, and the HMAC suites below run on it.
macro_rules! every_sha2 {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use crate::hash::sha2;
        use support::acvp::sha::Family;

        sha2_suites!(
            portable,
            sha2::portable::$variant,
            $file,
            $algorithm,
            Family::Sha2
        );

        #[cfg(target_arch = "aarch64")]
        sha2_suites!(
            armv8,
            sha2::aarch64::$variant,
            $file,
            $algorithm,
            Family::Sha2,
            "ARMv8 SHA2"
        );

        #[cfg(target_arch = "riscv64")]
        sha2_suites!(
            zknh,
            sha2::riscv64::zknh::$variant,
            $file,
            $algorithm,
            Family::Sha2,
            "RISC-V Zknh"
        );

        #[cfg(target_arch = "riscv64")]
        sha2_suites!(
            zvknh,
            sha2::riscv64::zvknh::$variant,
            $file,
            $algorithm,
            Family::Sha2,
            "RISC-V Zvknh"
        );
    };
}

/// Runs one SHA-3 digest's suites against each implementation this
/// architecture has, as `every_sha2!` does.
macro_rules! every_sha3 {
    ($variant:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use crate::hash::sha3;
        use support::acvp::sha::Family;

        sha2_suites!(
            portable,
            sha3::portable::$variant,
            $file,
            $algorithm,
            Family::Sha3
        );

        #[cfg(target_arch = "aarch64")]
        sha2_suites!(
            armv8,
            sha3::aarch64::$variant,
            $file,
            $algorithm,
            Family::Sha3,
            "ARMv8 SHA3"
        );
    };
}

/// SHA-224 (FIPS 180-4).
mod sha2_224 {
    every_sha2!(
        Sha224,
        "ACVP-SHA2-224-1.0/internalProjection.json",
        "SHA2-224"
    );

    #[cfg(target_arch = "x86_64")]
    sha2_suites!(
        shani,
        sha2::x86_64::Sha224,
        "ACVP-SHA2-224-1.0/internalProjection.json",
        "SHA2-224",
        Family::Sha2,
        "SHA-NI"
    );
}

/// SHA-256 (FIPS 180-4).
mod sha2_256 {
    every_sha2!(
        Sha256,
        "ACVP-SHA2-256-1.0/internalProjection.json",
        "SHA2-256"
    );

    #[cfg(target_arch = "x86_64")]
    sha2_suites!(
        shani,
        sha2::x86_64::Sha256,
        "ACVP-SHA2-256-1.0/internalProjection.json",
        "SHA2-256",
        Family::Sha2,
        "SHA-NI"
    );
}

/// SHA-384 (FIPS 180-4).
mod sha2_384 {
    every_sha2!(
        Sha384,
        "ACVP-SHA2-384-1.0/internalProjection.json",
        "SHA2-384"
    );
}

/// SHA-512 (FIPS 180-4).
mod sha2_512 {
    every_sha2!(
        Sha512,
        "ACVP-SHA2-512-1.0/internalProjection.json",
        "SHA2-512"
    );
}

/// SHA-512/224 (FIPS 180-4 section 5.3.6).
mod sha2_512_224 {
    every_sha2!(
        Sha512_224,
        "ACVP-SHA2-512-224-1.0/internalProjection.json",
        "SHA2-512/224"
    );
}

/// SHA-512/256 (FIPS 180-4 section 5.3.6).
mod sha2_512_256 {
    every_sha2!(
        Sha512_256,
        "ACVP-SHA2-512-256-1.0/internalProjection.json",
        "SHA2-512/256"
    );
}

/// SHA3-224 (FIPS 202).
mod sha3_224 {
    every_sha3!(
        Sha3_224,
        "ACVP-SHA3-224-2.0/internalProjection.json",
        "SHA3-224"
    );
}

/// SHA3-256 (FIPS 202).
mod sha3_256 {
    every_sha3!(
        Sha3_256,
        "ACVP-SHA3-256-2.0/internalProjection.json",
        "SHA3-256"
    );
}

/// SHA3-384 (FIPS 202).
mod sha3_384 {
    every_sha3!(
        Sha3_384,
        "ACVP-SHA3-384-2.0/internalProjection.json",
        "SHA3-384"
    );
}

/// SHA3-512 (FIPS 202).
mod sha3_512 {
    every_sha3!(
        Sha3_512,
        "ACVP-SHA3-512-2.0/internalProjection.json",
        "SHA3-512"
    );
}

/// Defines the SHAKE suites for one implementation.
macro_rules! shake_suites {
    ($name:ident, $ty:ty, $run:ident, $file:literal, $algorithm:literal) => {
        shake_suites!($name, $ty, $run, $file, $algorithm, "portable code");
    };
    ($name:ident, $ty:ty, $run:ident, $file:literal, $algorithm:literal,
     $what:literal) => {
        mod $name {
            use super::*;
            use crate::Error;

            fn supported() -> bool {
                match <$ty>::try_new() {
                    Ok(_) => true,
                    Err(Error::NotSupported) => {
                        eprintln!(concat!($what, " not available; skipping"));
                        false
                    }
                    Err(e) => panic!("{e}"),
                }
            }

            #[test]
            fn acvp_aft() {
                if supported() {
                    $run::run_aft($file, $algorithm, || {
                        <$ty>::try_new().expect("supported")
                    });
                }
            }

            /// Slow; run with `cargo test-extended`.
            #[test]
            #[ignore]
            fn acvp_mct() {
                if supported() {
                    $run::run_mct($file, $algorithm, || {
                        <$ty>::try_new().expect("supported")
                    });
                }
            }
        }
    };
}

/// Runs one SHAKE or cSHAKE function's suites against each
/// implementation this architecture has, as `every_sha2!` does.
/// `$run` is the driver: cSHAKE's runs over the bare sponge.
macro_rules! every_shake {
    ($variant:ident, $run:ident, $file:literal, $algorithm:literal) => {
        use super::*;
        use crate::hash::sha3;

        shake_suites!(
            portable,
            sha3::portable::$variant,
            $run,
            $file,
            $algorithm
        );

        #[cfg(target_arch = "aarch64")]
        shake_suites!(
            armv8,
            sha3::aarch64::$variant,
            $run,
            $file,
            $algorithm,
            "ARMv8 SHA3"
        );
    };
}

/// SHAKE128 (FIPS 202).
mod shake_128 {
    every_shake!(
        Shake128,
        shake_vectors,
        "ACVP-SHAKE-128-1.0/internalProjection.json",
        "SHAKE-128"
    );
}

/// SHAKE256 (FIPS 202).
mod shake_256 {
    every_shake!(
        Shake256,
        shake_vectors,
        "ACVP-SHAKE-256-1.0/internalProjection.json",
        "SHAKE-256"
    );
}

/// cSHAKE128 (SP 800-185).
mod cshake_128 {
    every_shake!(
        CShake128,
        cshake_vectors,
        "cSHAKE-128-1.0/internalProjection.json",
        "cSHAKE-128"
    );
}

/// cSHAKE256 (SP 800-185).
mod cshake_256 {
    every_shake!(
        CShake256,
        cshake_vectors,
        "cSHAKE-256-1.0/internalProjection.json",
        "cSHAKE-256"
    );
}

/// KMAC128 (SP 800-185), over whichever permutation the probe picks.
mod kmac_128 {
    use super::*;

    #[test]
    fn acvp_aft() {
        kmac_vectors::run_aft::<crate::mac::kmac::Kmac128>(
            "KMAC-128-1.0/internalProjection.json",
            "KMAC-128",
        );
    }
}

/// KMAC256 (SP 800-185).
mod kmac_256 {
    use super::*;

    #[test]
    fn acvp_aft() {
        kmac_vectors::run_aft::<crate::mac::kmac::Kmac256>(
            "KMAC-256-1.0/internalProjection.json",
            "KMAC-256",
        );
    }
}

/// The large data tests: messages of 1 to 8 GiB, which take the
/// length field past 2^32 bits. That field belongs to the shared
/// engine, one per SHA-2 word size, not to any variant or backend:
/// the variants differ only in starting value and truncation, and
/// the backends only in the compression function, and AFT and MCT
/// cover both of those for each. SHA-3 keeps no length at all, so
/// its one run checks only that nothing else breaks over 8 GiB. One
/// whole group each, on the best implementation the machine has.
mod sha_ldt {
    use super::*;
    use crate::hash::{sha2, sha3};
    use support::acvp::sha::Family;

    /// Gigabytes of hashing; run with `cargo test-extended`.
    #[test]
    #[ignore]
    fn sha256() {
        sha_vectors::run_ldt(
            "ACVP-SHA2-256-1.0/internalProjection.json",
            "SHA2-256",
            Family::Sha2,
            sha2::Sha256::new,
        );
    }

    /// Gigabytes of hashing; run with `cargo test-extended`.
    #[test]
    #[ignore]
    fn sha512() {
        sha_vectors::run_ldt(
            "ACVP-SHA2-512-1.0/internalProjection.json",
            "SHA2-512",
            Family::Sha2,
            sha2::Sha512::new,
        );
    }

    /// Thirty-two gigabytes of hashing; run with `cargo
    /// test-extended`.
    #[test]
    #[ignore]
    fn sha3_256() {
        sha_vectors::run_ldt(
            "ACVP-SHA3-256-2.0/internalProjection.json",
            "SHA3-256",
            Family::Sha3,
            sha3::Sha3_256::new,
        );
    }
}

/// Defines the HMAC suite for one hash. HMAC's own work does not
/// vary with the hash beneath it, and each hash has its own suites
/// above, so this runs on the dispatching type: the fastest the
/// processor has, and a check that the dispatch is sound. There is
/// nothing to skip: every processor can build a dispatching hash.
macro_rules! hmac_suite {
    ($name:ident, $hash:ty, $file:literal, $algorithm:literal) => {
        mod $name {
            use super::*;

            #[test]
            fn acvp_aft() {
                hmac_vectors::run_aft::<$hash>($file, $algorithm);
            }
        }
    };
}

/// HMAC (FIPS 198-1) over SHA-1.
mod hmac_sha1 {
    use super::*;
    use crate::hash::sha1;

    hmac_suite!(
        automatic,
        sha1::Sha1,
        "HMAC-SHA-1-1.0/internalProjection.json",
        "HMAC-SHA-1"
    );
}

/// HMAC (FIPS 198-1) over each SHA-2 variant.
mod hmac_sha2_224 {
    use super::*;
    use crate::hash::sha2;

    hmac_suite!(
        automatic,
        sha2::Sha224,
        "ACVP-HMAC-SHA2-224-1.0/internalProjection.json",
        "HMAC-SHA2-224"
    );
}

mod hmac_sha2_256 {
    use super::*;
    use crate::hash::sha2;

    hmac_suite!(
        automatic,
        sha2::Sha256,
        "ACVP-HMAC-SHA2-256-1.0/internalProjection.json",
        "HMAC-SHA2-256"
    );
}

mod hmac_sha2_384 {
    use super::*;
    use crate::hash::sha2;

    hmac_suite!(
        automatic,
        sha2::Sha384,
        "ACVP-HMAC-SHA2-384-1.0/internalProjection.json",
        "HMAC-SHA2-384"
    );
}

mod hmac_sha2_512 {
    use super::*;
    use crate::hash::sha2;

    hmac_suite!(
        automatic,
        sha2::Sha512,
        "ACVP-HMAC-SHA2-512-1.0/internalProjection.json",
        "HMAC-SHA2-512"
    );
}

mod hmac_sha2_512_224 {
    use super::*;
    use crate::hash::sha2;

    hmac_suite!(
        automatic,
        sha2::Sha512_224,
        "ACVP-HMAC-SHA2-512-224-1.0/internalProjection.json",
        "HMAC-SHA2-512/224"
    );
}

mod hmac_sha2_512_256 {
    use super::*;
    use crate::hash::sha2;

    hmac_suite!(
        automatic,
        sha2::Sha512_256,
        "ACVP-HMAC-SHA2-512-256-1.0/internalProjection.json",
        "HMAC-SHA2-512/256"
    );
}

/// HMAC over each SHA-3 digest, whose rates exceed any SHA-2 block,
/// which is the case the key canonicalisation has to get right.
mod hmac_sha3_224 {
    use super::*;
    use crate::hash::sha3;

    hmac_suite!(
        automatic,
        sha3::Sha3_224,
        "ACVP-HMAC-SHA3-224-1.0/internalProjection.json",
        "HMAC-SHA3-224"
    );
}

mod hmac_sha3_256 {
    use super::*;
    use crate::hash::sha3;

    hmac_suite!(
        automatic,
        sha3::Sha3_256,
        "ACVP-HMAC-SHA3-256-1.0/internalProjection.json",
        "HMAC-SHA3-256"
    );
}

mod hmac_sha3_384 {
    use super::*;
    use crate::hash::sha3;

    hmac_suite!(
        automatic,
        sha3::Sha3_384,
        "ACVP-HMAC-SHA3-384-1.0/internalProjection.json",
        "HMAC-SHA3-384"
    );
}

mod hmac_sha3_512 {
    use super::*;
    use crate::hash::sha3;

    hmac_suite!(
        automatic,
        sha3::Sha3_512,
        "ACVP-HMAC-SHA3-512-1.0/internalProjection.json",
        "HMAC-SHA3-512"
    );
}

/// PBKDF2 (SP 800-132). The vendored file covers HMAC-SHA-224 only,
/// and the function is generic over the hash, so one run suffices.
mod pbkdf2 {
    use super::*;

    #[test]
    fn acvp_aft() {
        pbkdf_vectors::run_aft::<crate::hash::sha2::Sha224>("SHA2-224");
    }
}

/// One ChaCha20 backend against the keystream Wycheproof's cases
/// imply, which is what a backend can get wrong.
macro_rules! chacha20_backend {
    ($name:ident, $backend:ty, $what:literal) => {
        mod $name {
            use super::*;

            #[test]
            fn wycheproof_keystream() {
                support::wycheproof::chacha20_poly1305::run_cipher::<$backend>(
                    $what,
                );
            }
        }
    };
}

/// ChaCha20-Poly1305 (RFC 8439), through Project Wycheproof's cases:
/// there is no ACVP suite for it. The whole AEAD runs under the
/// backend the processor picks, and each backend runs the keystream
/// those same cases imply.
mod chacha20_poly1305 {
    use super::*;
    use crate::cipher::chacha20;

    #[test]
    fn wycheproof() {
        support::wycheproof::chacha20_poly1305::run();
    }

    chacha20_backend!(portable, chacha20::portable::Portable, "portable");

    #[cfg(target_arch = "x86_64")]
    chacha20_backend!(avx2, chacha20::x86_64::Avx2, "AVX2");

    #[cfg(target_arch = "aarch64")]
    chacha20_backend!(neon, chacha20::aarch64::Neon, "NEON");

    #[cfg(target_arch = "riscv64")]
    chacha20_backend!(zvkb, chacha20::riscv64::Zvkb, "RISC-V vectors");

    #[cfg(target_arch = "riscv64")]
    chacha20_backend!(zbb, chacha20::riscv64::Zbb, "RISC-V rotates");
}

/// Key agreement: X25519, through ACVP's shared-secret and key
/// generation suites and Project Wycheproof's edge cases, and ECDH,
/// through Wycheproof alone: ACVP's KAS-ECC sample files hold only
/// the binary curves, and the ECDSA keyGen and keyVer suites cover
/// the same key handling.
///
/// ACVP's XECDH keyVer suite is not here; [`support::acvp::xecdh`]
/// says why.
mod kex {
    use super::*;

    #[test]
    fn wycheproof_ecdh() {
        support::wycheproof::ecdh::run();
    }

    #[test]
    fn wycheproof_x25519() {
        support::wycheproof::x25519::run();
    }

    #[test]
    fn acvp_xecdh() {
        support::acvp::xecdh::run();
    }

    #[test]
    fn acvp_xecdh_key_gen() {
        support::acvp::xecdh::run_key_gen();
    }
}

/// Key encapsulation: ML-KEM, through ACVP's keyGen and encapDecap
/// suites and Project Wycheproof's malformed keys and ciphertexts.
mod kem {
    use super::*;

    #[test]
    fn wycheproof_ml_kem() {
        support::wycheproof::ml_kem::run();
    }

    #[test]
    fn acvp_ml_kem_key_gen() {
        support::acvp::ml_kem::run_key_gen();
    }

    #[test]
    fn acvp_ml_kem_encap_decap() {
        support::acvp::ml_kem::run_encap_decap();
    }
}

/// Public-key encryption: RSA-OAEP, through ACVP's key transport
/// suite and Project Wycheproof's decryption cases, with the raw
/// decryption primitive beside them.
mod pke {
    use super::*;

    #[test]
    fn cfrg_hpke() {
        support::cfrg::run();
    }

    #[test]
    fn acvp_kts_ifc() {
        support::acvp::kts_ifc::run();
    }

    #[test]
    fn acvp_rsa_decryption_primitive() {
        support::acvp::rsa_primitive::run_decryption_primitive();
    }
}

/// Signatures: ECDSA, Ed25519, ML-DSA, SLH-DSA and RSA, through ACVP
/// and Project Wycheproof.
///
/// ACVP RSA keyGen is deliberately absent: its vectors replay a
/// seeded candidate stream, and `generate` draws from a live random
/// source.
mod sig {
    use super::*;

    #[test]
    fn wycheproof_ecdsa() {
        support::wycheproof::ecdsa::run();
    }

    #[test]
    fn wycheproof_ed25519() {
        support::wycheproof::ed25519::run();
    }

    #[test]
    fn wycheproof_ml_dsa() {
        support::wycheproof::ml_dsa::run();
    }

    #[test]
    fn acvp_ml_dsa_key_gen() {
        support::acvp::ml_dsa::run_key_gen();
    }

    #[test]
    fn acvp_ml_dsa_sig_gen() {
        support::acvp::ml_dsa::run_sig_gen();
    }

    #[test]
    fn acvp_ml_dsa_sig_ver() {
        support::acvp::ml_dsa::run_sig_ver();
    }

    #[test]
    fn acvp_slh_dsa_key_gen() {
        support::acvp::slh_dsa::run_key_gen();
    }

    /// One signature per group, every set and both modes; the whole
    /// file is a minute of hashing and runs under `test-extended`.
    #[test]
    fn acvp_slh_dsa_sig_gen() {
        support::acvp::slh_dsa::run_sig_gen(false);
    }

    #[test]
    #[ignore]
    fn acvp_slh_dsa_sig_gen_all() {
        support::acvp::slh_dsa::run_sig_gen(true);
    }

    #[test]
    fn acvp_slh_dsa_sig_ver() {
        support::acvp::slh_dsa::run_sig_ver();
    }

    #[test]
    fn acvp_ecdsa_key_gen() {
        support::acvp::ecdsa::run_key_gen();
    }

    #[test]
    fn acvp_ecdsa_key_ver() {
        support::acvp::ecdsa::run_key_ver();
    }

    #[test]
    fn acvp_ecdsa_sig_ver() {
        support::acvp::ecdsa::run_sig_ver();
    }

    #[test]
    fn acvp_ecdsa_sig_gen_answers() {
        support::acvp::ecdsa::run_sig_gen();
    }

    #[test]
    fn acvp_ecdsa_det_sig_gen() {
        support::acvp::ecdsa::run_det_sig_gen();
    }

    #[test]
    fn wycheproof_rsa() {
        support::wycheproof::rsa::run();
    }

    #[test]
    fn acvp_eddsa_key_gen() {
        support::acvp::eddsa::run_key_gen();
    }

    #[test]
    fn acvp_eddsa_key_ver() {
        support::acvp::eddsa::run_key_ver();
    }

    #[test]
    fn acvp_eddsa_sig_gen() {
        support::acvp::eddsa::run_sig_gen();
    }

    #[test]
    fn acvp_eddsa_sig_ver() {
        support::acvp::eddsa::run_sig_ver();
    }

    #[test]
    fn acvp_rsa_sig_ver() {
        support::acvp::rsa_sig::run_sig_ver();
    }

    #[test]
    fn acvp_rsa_sig_ver_186_4() {
        support::acvp::rsa_sig::run_sig_ver_186_4();
    }

    #[test]
    fn acvp_rsa_sig_gen_answers() {
        support::acvp::rsa_sig::run_sig_gen();
    }

    #[test]
    fn acvp_rsa_signature_primitive() {
        support::acvp::rsa_primitive::run_signature_primitive();
    }
}

/// HKDF, as SP 800-56Cr2's key-derivation step.
mod hkdf {
    use super::*;

    #[test]
    fn acvp_kda_hkdf() {
        support::acvp::kda_hkdf::run();
    }
}

/// The TLS 1.2 PRF, as RFC 7627's extended master secret and the key
/// block.
mod tls12 {
    use super::*;

    #[test]
    fn acvp_tls12_kdf() {
        support::acvp::tls12_kdf::run();
    }
}

/// Every implementation this build holds, whether this processor
/// can run it, and whether that is the right answer.
///
/// A suite whose implementation is absent skips, and a skip reads as
/// a pass, so this is where a log says what was actually exercised:
///
/// ```text
/// cargo test --lib acvp::inventory -- --nocapture
/// ```
///
/// It is also where the probes are held to account. Each row says
/// which processor features its implementation needs, in the names
/// the standard library detects them by, and the row has to be
/// available exactly when the processor has them all. That fails in
/// both directions: a probe that asks for less than its loop uses is
/// caught on the first processor that has the one and not the other,
/// before the loop is run there; and a probe that has started saying
/// no everywhere, which would otherwise leave its implementation
/// untested behind a run of passing skips, is caught on any machine
/// that has the features. Emulated processors are what make the
/// first of those happen: see the jobs in `ci.yml`.
///
/// A job that emulates a processor says what it expects of it in
/// `SCYTALE_CPU_FEATURES`, a list separated by spaces. The list is
/// checked against what the processor reports, so that an emulator
/// too old to offer an extension fails the job rather than quietly
/// testing nothing; and on RISC-V, where the standard library cannot
/// yet be asked, the list is all the rows have to be checked against.
mod inventory {
    use std::cell::RefCell;
    use std::string::String;
    use std::vec::Vec;
    #[allow(unused_imports)]
    use std::{format, println};

    use crate::Error;
    use crate::cipher::chacha20::Backend;
    use crate::cipher::{aes, chacha20};
    use crate::hash::{sha2, sha3};

    /// Where an emulating job declares the processor's features.
    const DECLARED: &str = "SCYTALE_CPU_FEATURES";

    /// Every feature a row below is written in terms of.
    #[cfg(target_arch = "x86_64")]
    const FEATURES: &[&str] = &[
        "aes",
        "ssse3",
        "sse4.1",
        "avx",
        "avx2",
        "vaes",
        "pclmulqdq",
        "vpclmulqdq",
        "sha",
        "adx",
        "bmi2",
    ];
    #[cfg(target_arch = "aarch64")]
    const FEATURES: &[&str] = &["aes", "pmull", "sha2", "sha3"];
    #[cfg(target_arch = "riscv64")]
    const FEATURES: &[&str] = &[
        "v", "zbb", "zbkb", "zkne", "zknd", "zknh", "zvkned", "zvknha",
        "zvknhb", "zvbb", "zvkb", "zvkg",
    ];
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )))]
    const FEATURES: &[&str] = &[];

    /// What the standard library makes of `feature`, which is an
    /// answer reached without any of this crate's probes; `None`
    /// where it has no stable way to be asked.
    #[allow(unused_variables)]
    fn detected(feature: &str) -> Option<bool> {
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::is_x86_feature_detected as has;
            return Some(match feature {
                "aes" => has!("aes"),
                "ssse3" => has!("ssse3"),
                "sse4.1" => has!("sse4.1"),
                "avx" => has!("avx"),
                "avx2" => has!("avx2"),
                "vaes" => has!("vaes"),
                "pclmulqdq" => has!("pclmulqdq"),
                "vpclmulqdq" => has!("vpclmulqdq"),
                "sha" => has!("sha"),
                "adx" => has!("adx"),
                "bmi2" => has!("bmi2"),
                _ => return None,
            });
        }
        #[cfg(target_arch = "aarch64")]
        {
            use std::arch::is_aarch64_feature_detected as has;
            return Some(match feature {
                "aes" => has!("aes"),
                "pmull" => has!("pmull"),
                "sha2" => has!("sha2"),
                "sha3" => has!("sha3"),
                _ => return None,
            });
        }
        #[allow(unreachable_code)]
        None
    }

    /// The table as it is printed, and what was wrong with it.
    struct Audit {
        /// What the job said the processor has, if it said.
        declared: Option<Vec<String>>,
        wrong: RefCell<Vec<String>>,
    }

    impl Audit {
        fn new() -> Self {
            let declared = std::env::var(DECLARED).ok().map(|list| {
                list.split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>()
            });
            let audit = Audit {
                declared,
                wrong: RefCell::new(Vec::new()),
            };
            let Some(declared) = &audit.declared else {
                return audit;
            };
            for feature in declared {
                assert!(
                    FEATURES.contains(&feature.as_str()),
                    "{DECLARED} names {feature}, which no row knows"
                );
            }
            // The emulator has to be offering what the job thinks it
            // is, or the job is not testing what it says.
            for &feature in FEATURES {
                let said = declared.iter().any(|d| d == feature);
                if let Some(found) = detected(feature)
                    && found != said
                {
                    audit.wrong.borrow_mut().push(format!(
                        "{feature}: the processor reports {found}, \
                         {DECLARED} says {said}"
                    ));
                }
            }
            audit
        }

        /// Whether the processor has `feature`, by the job's word
        /// where it gave one and the standard library's otherwise.
        fn has(&self, feature: &str) -> Option<bool> {
            match &self.declared {
                Some(declared) => Some(declared.iter().any(|d| d == feature)),
                None => detected(feature),
            }
        }

        /// Whether an implementation needing `requires` should be
        /// available. Every entry is needed; an entry `a|b` is met
        /// by either. `None` where there is nothing to ask.
        fn expects(&self, requires: &[&str]) -> Option<bool> {
            let mut all = true;
            for entry in requires {
                let mut any = false;
                for feature in entry.split('|') {
                    any |= self.has(feature)?;
                }
                all &= any;
            }
            Some(all)
        }

        fn report(&self, name: &str, available: bool, requires: &[&str]) {
            self.row("", name, available, requires);
        }

        /// One row, under the heading `suite` where it has one: the
        /// modes all call their implementations by the same names.
        fn row(
            &self,
            suite: &str,
            name: &str,
            available: bool,
            requires: &[&str],
        ) {
            let state = if available { "run" } else { "not available" };
            println!("  {name:<32} {state}");
            if let Some(expected) = self.expects(requires)
                && expected != available
            {
                self.wrong.borrow_mut().push(format!(
                    "{suite} {name}: {state}, but it needs {requires:?} \
                     and the processor {} them",
                    if expected { "has" } else { "lacks one of" }
                ));
            }
        }

        fn finish(self) {
            let source = match (&self.declared, FEATURES.first()) {
                (Some(_), _) => DECLARED,
                (None, Some(&first)) if detected(first).is_some() => {
                    "the standard library's detection"
                }
                _ => "nothing: there is no way to ask here",
            };
            println!("checked against {source}\n");
            let wrong = self.wrong.into_inner();
            assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
        }
    }

    /// What a mode's implementation needs. The counter, chaining and
    /// tweak loops need what the cipher's own instructions need, in
    /// the encoding they are written in; the two with a hash in the
    /// loop need its multiply as well.
    fn mode_requires(suite: &str, name: &str) -> Vec<&'static str> {
        let hashes = matches!(suite, "AES-GCM" | "AES-GCM-SIV");
        let mut needs: Vec<&'static str> = Vec::new();
        match name {
            // Written in the VEX encodings, so AES-NI is not enough.
            "aesni" => {
                needs.extend(["aes", "ssse3", "avx"]);
                if hashes {
                    needs.push("pclmulqdq");
                }
            }
            "vaes" => {
                needs.extend(["aes", "ssse3", "avx", "avx2", "vaes"]);
                if hashes {
                    needs.extend(["pclmulqdq", "vpclmulqdq"]);
                }
            }
            "armv8" => {
                needs.push("aes");
                if hashes {
                    needs.push("pmull");
                }
            }
            // The counters are reversed with `vrev8`, which either
            // of two extensions brings.
            "zvkned" => {
                needs.extend(["v", "zvkned", "zvbb|zvkb"]);
                if hashes {
                    needs.push("zvkg");
                }
            }
            _ => {}
        }
        needs
    }

    /// Every implementation of every mode that has more than one,
    /// under the cipher `C`.
    fn modes<C>(audit: &Audit)
    where
        C: crate::cipher::BlockCipher<
                Block = [u8; 16],
                Key = crate::Key<[u8; 16]>,
            >,
    {
        use crate::aead::{ccm, gcm, gcm_siv};
        use crate::cipher::mode::{cbc, ctr, xts};
        use crate::implementation::Implementation;

        let key = crate::Key::from([0x42u8; 16]);
        let tweak = crate::Key::from([0x99u8; 16]);
        let one = |suite: &str,
                   all: &[Implementation],
                   has: &dyn Fn(Implementation) -> bool| {
            println!("{suite}");
            for &i in all {
                let needs = mode_requires(suite, i.name());
                audit.row(suite, i.name(), has(i), &needs);
            }
        };
        one("AES-CBC", cbc::CHOICES, &|i| {
            cbc::Cbc::<C>::with_implementation(&key, i).is_some()
        });
        one("AES-CTR", ctr::CHOICES, &|i| {
            ctr::Ctr::<C>::with_implementation(&key, i).is_some()
        });
        one("AES-XTS", xts::CHOICES, &|i| {
            xts::Xts::<C>::with_implementation(&key, &tweak, i).is_some()
        });
        one("AES-CCM", ccm::CHOICES, &|i| {
            ccm::Ccm::<C>::with_implementation(&key, i).is_some()
        });
        one("AES-GCM", gcm::CHOICES, &|i| {
            gcm::Gcm::<C>::with_implementation(&key, i).is_some()
        });
        one("AES-GCM-SIV", gcm_siv::CHOICES, &|i| {
            gcm_siv::GcmSiv::<C>::with_implementation(&key, i).is_some()
        });
    }

    /// Whether a hash can be built on this processor. The named
    /// backends ask the probe, which is what can answer no; the
    /// dispatching types pass their own infallible constructor.
    fn hash<H>(start: fn() -> Result<H, Error>) -> bool {
        available(start().map(|_| ()))
    }

    /// `NotSupported` is the absence of instructions; anything else
    /// is a fault worth failing for.
    fn available(result: Result<(), Error>) -> bool {
        match result {
            Ok(()) => true,
            Err(Error::NotSupported) => false,
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn implementations() {
        let audit = Audit::new();
        println!("\nAES");
        audit.report("aes::Aes", true, &[]);
        audit.report(
            "aes::portable::bitsliced::Aes",
            aes::portable::bitsliced::Aes::<16>::supported(),
            &[],
        );
        audit.report(
            "aes::portable::ttable::Aes",
            aes::portable::ttable::Aes::<16>::supported(),
            &[],
        );
        #[cfg(target_arch = "x86_64")]
        {
            // The cipher alone is in the legacy encodings; it is the
            // loops over it, below, that are not.
            audit.report(
                "aes::x86_64::aesni::Aes",
                aes::x86_64::aesni::Aes::<16>::supported(),
                &["aes", "ssse3"],
            );
            audit.report(
                "aes::x86_64::vaes::Aes",
                aes::x86_64::vaes::Aes::<16>::supported(),
                &["aes", "ssse3", "avx", "avx2", "vaes"],
            );
        }
        #[cfg(target_arch = "aarch64")]
        audit.report(
            "aes::aarch64::armv8::Aes",
            aes::aarch64::armv8::Aes::<16>::supported(),
            &["aes"],
        );
        #[cfg(target_arch = "riscv64")]
        {
            audit.report(
                "aes::riscv64::zkn::Aes",
                aes::riscv64::zkn::Aes::<16>::supported(),
                &["zkne", "zknd"],
            );
            audit.report(
                "aes::riscv64::zvkned::Aes",
                aes::riscv64::zvkned::Aes::<16>::supported(),
                &["v", "zvkned"],
            );
        }

        // The modes and AEADs written out for particular
        // instructions, which are implementations in their own right
        // and validated by name like the ciphers above.
        modes::<aes::Aes128>(&audit);

        // SHA-256 and SHA-512 are listed apart: they are different
        // instructions, and a processor can have one without the
        // other.
        println!("SHA-2");
        audit.report("sha2::Sha256", hash(|| Ok(sha2::Sha256::new())), &[]);
        audit.report("sha2::Sha512", hash(|| Ok(sha2::Sha512::new())), &[]);
        audit.report(
            "sha2::portable::Sha256",
            hash(sha2::portable::Sha256::try_new),
            &[],
        );
        audit.report(
            "sha2::portable::Sha512",
            hash(sha2::portable::Sha512::try_new),
            &[],
        );
        // The rounds are the SHA instructions, and around them the
        // loop shuffles bytes and inserts and blends words.
        #[cfg(target_arch = "x86_64")]
        audit.report(
            "sha2::x86_64::Sha256",
            hash(sha2::x86_64::Sha256::try_new),
            &["sha", "ssse3", "sse4.1"],
        );
        #[cfg(target_arch = "aarch64")]
        {
            audit.report(
                "sha2::aarch64::Sha256",
                hash(sha2::aarch64::Sha256::try_new),
                &["sha2"],
            );
            // The standard library reports SHA-512 and SHA-3
            // together, as one feature, which is how they arrive.
            audit.report(
                "sha2::aarch64::Sha512",
                hash(sha2::aarch64::Sha512::try_new),
                &["sha3"],
            );
        }
        #[cfg(target_arch = "riscv64")]
        {
            audit.report(
                "sha2::riscv64::zknh::Sha256",
                hash(sha2::riscv64::zknh::Sha256::try_new),
                &["zknh"],
            );
            audit.report(
                "sha2::riscv64::zknh::Sha512",
                hash(sha2::riscv64::zknh::Sha512::try_new),
                &["zknh"],
            );
            audit.report(
                "sha2::riscv64::zvknh::Sha256",
                hash(sha2::riscv64::zvknh::Sha256::try_new),
                &["v", "zvknha|zvknhb", "zvbb|zvkb"],
            );
            audit.report(
                "sha2::riscv64::zvknh::Sha512",
                hash(sha2::riscv64::zvknh::Sha512::try_new),
                &["v", "zvknhb", "zvbb|zvkb"],
            );
        }

        println!("SHA-3");
        audit.report("sha3::Sha3_256", hash(|| Ok(sha3::Sha3_256::new())), &[]);
        audit.report(
            "sha3::portable::Sha3_256",
            hash(sha3::portable::Sha3_256::try_new),
            &[],
        );
        #[cfg(target_arch = "aarch64")]
        audit.report(
            "sha3::aarch64::Sha3_256",
            hash(sha3::aarch64::Sha3_256::try_new),
            &["sha3"],
        );

        println!("ChaCha20");
        audit.report(
            "chacha20::portable::Portable",
            chacha20::portable::Portable::supported(),
            &[],
        );
        #[cfg(target_arch = "x86_64")]
        audit.report(
            "chacha20::x86_64::Avx2",
            chacha20::x86_64::Avx2::supported(),
            &["avx2"],
        );
        #[cfg(target_arch = "aarch64")]
        audit.report(
            "chacha20::aarch64::Neon",
            chacha20::aarch64::Neon::supported(),
            &[],
        );
        #[cfg(target_arch = "riscv64")]
        audit.report(
            "chacha20::riscv64::Zvkb",
            chacha20::riscv64::Zvkb::supported(),
            &["v", "zvbb|zvkb"],
        );
        #[cfg(target_arch = "riscv64")]
        audit.report(
            "chacha20::riscv64::Zbb",
            chacha20::riscv64::Zbb::supported(),
            &["zbb|zbkb"],
        );

        // The arithmetic behind the curves, RSA and the MACs, which
        // has no suite of its own to skip and so no other place to
        // say whether its written-out path was the one that ran.
        #[cfg(target_arch = "x86_64")]
        {
            println!("Arithmetic");
            audit.report(
                "montgomery::x86_64::Adx",
                crate::math::montgomery::x86_64::probe().is_some(),
                &["adx", "bmi2"],
            );
        }
        audit.finish();
    }
}
