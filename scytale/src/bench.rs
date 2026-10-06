//! Throughput of the primitives, in the manner of `openssl speed`,
//! and the cost of the operations that have no throughput to
//! measure.
//!
//! Everything the library implements is here. A primitive that runs
//! over a buffer is reported as a rate at six sizes, from one block
//! to sixteen kilobytes: the small end shows what a call costs
//! before any data moves, the large end the steady state, and the
//! distance between them is what says whether a faster bulk path
//! would need a short-message fallback beside it. A primitive whose
//! cost is the call rather than the data, which is every key
//! operation, both key derivations and the two format-preserving
//! modes, is reported instead as operations a second and the time
//! one takes.
//!
//! Every implementation gets one section, named for the instructions
//! it runs on, and nothing is measured twice. A mode written out for
//! those instructions is measured as itself; a mode with nothing
//! written for them appears only where the portable construction over
//! that cipher is what runs. The SHA-2, SHA-3 and ChaCha20
//! implementations follow in sections of their own. What chooses
//! inside itself and cannot be named from out here -- SHA-1, the
//! generator, Poly1305 and the AEAD over ChaCha20 -- is under
//! `dispatching`. The operation groups are named for the module they
//! come from: `kdf`, `kex`, `sig`, `sig-pq`, `kem`, `pke` and `fpe`.
//!
//! ```text
//! scripts/bench                    # everything
//! scripts/bench gcm aesni          # rows matching both
//! scripts/bench sha                # the hashes only
//! scripts/bench sig                # signatures, both kinds
//! scripts/bench --seconds 0.25     # a quicker sweep
//! scripts/bench --self-test        # check the harness
//! ```
//!
//! # Reading the numbers
//!
//! Counter mode and GMAC are the two halves of GCM measured apart:
//! the keystream without the hash, and the hash without the
//! keystream. If the reciprocal of the GCM rate is close to the sum
//! of their reciprocals, the two halves are running one after the
//! other and a single loop that interleaved them would have the whole
//! of that difference to win. If GCM already beats that sum, the
//! processor is overlapping them on its own.
//!
//! Key wrapping is six passes over its input by construction, so it
//! reads an order of magnitude below the mode rows above it. CFB1 is
//! a block operation per bit, and reads as such.
//!
//! ML-DSA signing repeats until a candidate passes, so its cost
//! depends on the message and not only on the parameter set; a
//! stronger set is not reliably slower. Both key generation figures
//! for RSA and the signature figures for SLH-DSA vary for the same
//! kind of reason.
//!
//! A laptop measured on battery reports about half these numbers,
//! evenly across every row, which is the clock and not the code.
//!
use std::env;
use std::fmt::Write as _;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cpu_time::ThreadTime;

use crate::Key;
use crate::aead::{Aead, Ccm, ChaCha20Poly1305, Gcm, GcmSiv, Xpn};
use crate::cipher::chacha20;
use crate::cipher::mode::{Cbc, Cfb1, Cfb8, Cfb128, Ctr, Kw, Kwp, Ofb, Xts};
use crate::cipher::mode::{Ff1, Ff3_1};
use crate::cipher::{BlockCipher, aes};
use crate::implementation::Implementation;
#[allow(unused_imports)]
use std::{
    boxed::Box, eprintln, format, print, println, string::String,
    string::ToString, vec, vec::Vec,
};

/// The portable AES implementations at a key width; their paths
/// alone are too long.
type Bitsliced<const K: usize> = aes::portable::bitsliced::Aes<K>;
type Ttable<const K: usize> = aes::portable::ttable::Aes<K>;
use crate::BlockType;
use crate::Error;
use crate::Random;
use crate::hash::sha1::Sha1;
use crate::hash::{Hash, Xof, XofReader};
use crate::hash::{sha2, sha3};
use crate::kdf::{hkdf, pbkdf2};
use crate::kex::{ecdh, x25519};
use crate::mac::Mac;
use crate::mac::cmac::Cmac;
use crate::mac::hmac::Hmac;
use crate::mac::kmac::Kmac128;
use crate::mac::poly1305::Poly1305;
use crate::pke::rsa as oaep;
use crate::random::CtrDrbg;
use crate::sig::{ecdsa, ed25519, rsa};

/// Buffer sizes reported, the ones `openssl speed` uses.
const SIZES: [usize; 6] = [16, 64, 256, 1024, 8192, 16384];

/// CPU time spent on each cell unless `--seconds` says otherwise.
const DEFAULT_BUDGET: Duration = Duration::from_millis(1000);

/// How long a calibration batch should last. Long enough that the two
/// clock reads around it are lost in the noise, short enough that
/// finding the batch size costs little.
const CALIBRATION: Duration = Duration::from_millis(10);

/// Ceiling on the calibrated batch, so that an operation too quick to
/// reach [`CALIBRATION`] cannot spin the search forever.
const MAX_BATCH: u64 = 1 << 32;

/// One operation, ready to run over a buffer.
///
/// Boxed and called through the vtable, which costs a couple of
/// nanoseconds an iteration. That is invisible at the larger sizes
/// and a few percent at sixteen bytes, and it falls on every row
/// alike, so rows stay comparable with each other.
type Operation<'a> = Box<dyn FnMut(&mut [u8]) + 'a>;

/// A named operation.
type Task<'a> = (&'static str, Operation<'a>);

/// Measures. Ignored by default, since a sweep takes minutes and a
/// test run should not; `scripts/bench` runs it.
///
/// The arguments are in `SCYTALE_BENCH`, since the test harness owns
/// the command line.
#[test]
#[ignore = "measures; run it with scripts/bench"]
fn speed() {
    let arguments = env::var("SCYTALE_BENCH").unwrap_or_default();
    let words = arguments.split_whitespace().map(String::from);
    let options = match Options::parse(words) {
        Ok(Some(options)) => options,
        // `--help`, which has printed itself.
        Ok(None) => return,
        Err(message) => panic!("speed: {message}"),
    };
    if options.self_test {
        assert!(self_test(), "self-test");
        return;
    }
    // A build with debug assertions left on is not the release
    // profile that `scripts/bench` uses, so any figure it produced
    // would describe the unoptimised code rather than the shipped
    // code. That is also how `cargo test --benches` arrives here, and
    // a five minute sweep is not what asking for tests means.
    if cfg!(debug_assertions) {
        println!(
            "speed: this build has debug assertions on, so any figure\n\
             would describe unoptimised code. Checking the harness\n\
             instead; `scripts/bench` measures."
        );
        assert!(self_test(), "self-test");
        return;
    }
    if !report(&options) {
        // Nothing ran. With filters that is a request for rows which
        // do not exist, which `report` has just explained; there is
        // nothing to measure and nothing wrong. With no filters it
        // means the harness itself measured nothing, which is a fault.
        assert!(
            !options.filters.is_empty(),
            "no filters, and still nothing measured"
        );
    }
}

/// What the command line asked for.
struct Options {
    /// CPU time to spend on each cell.
    budget: Duration,
    /// Words that a row's name must all contain to be run.
    filters: Vec<String>,
    /// Check the harness itself instead of benchmarking.
    self_test: bool,
}

impl Options {
    /// Parses arguments, or returns `None` when the work is done
    /// already, as it is for `--help`.
    fn parse(
        args: impl Iterator<Item = String>,
    ) -> Result<Option<Self>, String> {
        let mut options = Options {
            budget: DEFAULT_BUDGET,
            filters: Vec::new(),
            self_test: false,
        };
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    print!("{USAGE}");
                    return Ok(None);
                }
                "--self-test" => options.self_test = true,
                "--seconds" => {
                    let value = args
                        .next()
                        .ok_or("--seconds wants a number of seconds")?;
                    let seconds: f64 = value
                        .parse()
                        .map_err(|_| format!("not a number: {value}"))?;
                    if !(seconds.is_finite() && seconds > 0.0) {
                        return Err(format!("not a duration: {value}"));
                    }
                    options.budget = Duration::from_secs_f64(seconds);
                }
                // Cargo appends this when it runs a bench target,
                // saying only that this is a benchmark run, which is
                // what the target does anyway.
                "--bench" => {}
                // Cargo appends this one instead when a bench
                // target is reached through `cargo test`.
                "--test" => options.self_test = true,
                other if other.starts_with('-') => {
                    return Err(format!("unknown option: {other}"));
                }
                other => options.filters.push(other.to_ascii_lowercase()),
            }
        }
        Ok(Some(options))
    }

    /// Whether a row belongs in this run. Every filter word must
    /// appear somewhere in the implementation or algorithm name, so
    /// `gcm aesni` narrows to one implementation's GCM rows. A word
    /// may offer alternatives separated by commas, so `ctr,ecb-enc`
    /// keeps rows matching either.
    ///
    /// The two go together: a comparison between rows only means
    /// anything when they were measured in the same run, since the
    /// clock and which core the thread lands on both move between
    /// runs, and a conjunction alone cannot ask for two rows.
    fn wants(&self, implementation: &str, algorithm: &str) -> bool {
        let name = format!("{implementation} {algorithm}");
        self.filters
            .iter()
            .all(|filter| filter.split(',').any(|word| name.contains(word)))
    }
}

const USAGE: &str = "\
usage: scripts/bench [options] [filter...]

  --seconds N   CPU time to spend on each measurement (default 1)
  --self-test   check the harness instead of benchmarking
  --help        this text

A filter is a bare word; a row runs when its implementation and
algorithm names together contain every filter given. Commas inside a
word offer alternatives, so `aesni ctr,ecb-enc` keeps both of those
rows, measured in the one run and so comparable.
";

/// Runs every implementation the processor supports: measures every
/// section the filters allow, and says whether any row ran.
fn report(options: &Options) -> bool {
    println!(
        "Throughput in megabytes a second (10^6), by buffer size in \
         bytes.\nEach figure is CPU time on this thread, over \
         {:.3} seconds of work.",
        options.budget.as_secs_f64()
    );

    // One section per implementation, named for the instructions it
    // runs on. A section exists only on the architecture that has
    // them, is skipped when the processor says no, and leaves out any
    // row whose suite has nothing written for those instructions.
    let mut ran = false;
    #[cfg(target_arch = "x86_64")]
    {
        use crate::cipher::aes::x86_64;
        ran |= section::<x86_64::vaes::Aes<16>, x86_64::vaes::Aes<32>>(
            "vaes",
            Implementation::Vaes,
            options,
        );
        ran |= section::<x86_64::aesni::Aes<16>, x86_64::aesni::Aes<32>>(
            "aesni",
            Implementation::Aesni,
            options,
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        use crate::cipher::aes::aarch64;
        ran |= section::<aarch64::armv8::Aes<16>, aarch64::armv8::Aes<32>>(
            "armv8",
            Implementation::Armv8,
            options,
        );
    }
    #[cfg(target_arch = "riscv64")]
    {
        use crate::cipher::aes::riscv64;
        ran |= section::<riscv64::zvkned::Aes<16>, riscv64::zvkned::Aes<32>>(
            "zvkned",
            Implementation::Zvkned,
            options,
        );
        // The scalar cipher has no mode written against it, so its
        // rows are the portable constructions over it.
        ran |= section::<riscv64::zkn::Aes<16>, riscv64::zkn::Aes<32>>(
            "zkn",
            Implementation::Portable,
            options,
        );
    }
    ran |= section::<Bitsliced<16>, Bitsliced<32>>(
        "bitsliced",
        Implementation::Portable,
        options,
    );
    ran |= section::<Ttable<16>, Ttable<32>>(
        "ttable",
        Implementation::Portable,
        options,
    );

    // The hashes, likewise. SHA-224 and SHA-384 cost the same as
    // SHA-256 and SHA-512 and are not measured separately.
    #[cfg(target_arch = "x86_64")]
    {
        ran |= hash_section(
            "shani",
            options,
            sha2::x86_64::Sha256::try_new,
            sha2::portable::Sha512::try_new,
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        ran |= hash_section(
            "armv8",
            options,
            sha2::aarch64::Sha256::try_new,
            sha2::aarch64::Sha512::try_new,
        );
    }
    #[cfg(target_arch = "riscv64")]
    {
        ran |= hash_section(
            "zvknh",
            options,
            sha2::riscv64::zvknh::Sha256::try_new,
            sha2::riscv64::zvknh::Sha512::try_new,
        );
        ran |= hash_section(
            "zknh",
            options,
            sha2::riscv64::zknh::Sha256::try_new,
            sha2::riscv64::zknh::Sha512::try_new,
        );
    }
    ran |= hash_section(
        "portable",
        options,
        sha2::portable::Sha256::try_new,
        sha2::portable::Sha512::try_new,
    );

    // ChaCha20, one section per way of computing the keystream.
    #[cfg(target_arch = "x86_64")]
    {
        ran |= chacha_section::<chacha20::x86_64::ChaCha20>("avx2", options);
    }
    #[cfg(target_arch = "aarch64")]
    {
        ran |= chacha_section::<chacha20::aarch64::ChaCha20>("neon", options);
    }
    #[cfg(target_arch = "riscv64")]
    {
        ran |= chacha_section::<chacha20::riscv64::zvkb::ChaCha20>(
            "zvkb", options,
        );
        ran |=
            chacha_section::<chacha20::riscv64::zbb::ChaCha20>("zbb", options);
    }
    ran |= chacha_section::<chacha20::portable::ChaCha20>("portable", options);

    // SHA-3: one permutation under every function, so one hardware
    // section, and only AArch64 has the instructions.
    #[cfg(target_arch = "aarch64")]
    {
        ran |= sha3_section(
            "armv8",
            options,
            (
                sha3::aarch64::Sha3_256::try_new,
                sha3::aarch64::Sha3_512::try_new,
                sha3::aarch64::Shake128::try_new,
                sha3::aarch64::Shake256::try_new,
            ),
        );
    }
    ran |= sha3_section(
        "portable",
        options,
        (
            sha3::portable::Sha3_256::try_new,
            sha3::portable::Sha3_512::try_new,
            sha3::portable::Shake128::try_new,
            sha3::portable::Shake256::try_new,
        ),
    );
    ran |= single_section(options);

    ran |= kdf_ops(options);
    ran |= kex_ops(options);
    ran |= sig_ops(options);
    ran |= pq_sig_ops(options);
    ran |= kem_ops(options);
    ran |= pke_ops(options);
    ran |= fpe_ops(options);

    if !ran {
        explain(&options.filters);
    }
    ran
}

/// Every row name the harness knows, for saying what a filter could
/// have meant.
///
/// The lists are per family and live beside the code that measures
/// each, so this gathers them rather than being a second copy to keep
/// in step.
fn every_row_name() -> impl Iterator<Item = &'static str> {
    ALGORITHMS
        .iter()
        .chain(HASHES.iter())
        .chain(CHACHA.iter())
        .chain(DISPATCHING.iter())
        .chain(KDF_JOBS.iter())
        .chain(KEX_JOBS.iter())
        .chain(SIG_JOBS.iter())
        .chain(PQ_SIG_JOBS.iter())
        .chain(KEM_JOBS.iter())
        .chain(PKE_JOBS.iter())
        .chain(FPE_JOBS.iter())
        .copied()
}

/// Says what a filter that selected nothing could have meant.
///
/// Nearly always one word is spelt right but asks for a row that does
/// not exist, or two words are each fine and have no row in common --
/// `ctr aes-256`, where counter mode has only a 128-bit row. Showing
/// each word beside the rows it does match makes both visible.
fn explain(filters: &[String]) {
    eprintln!("speed: no row matches every filter word.");
    for filter in filters {
        let matched: Vec<&str> = every_row_name()
            .filter(|name| filter.split(',').any(|word| name.contains(word)))
            .collect();
        if matched.is_empty() {
            eprintln!(
                "  {filter:<16} no row name holds this; \
                 an implementation, perhaps?"
            );
        } else {
            eprintln!("  {filter:<16} {}", matched.join(" "));
        }
    }
    eprintln!(
        "A row runs when its implementation and algorithm names \
         together hold\nevery word given. Commas inside a word offer \
         alternatives; see --help."
    );
}

/// Measures one implementation, returning whether it ran anything.
///
/// An implementation the processor cannot run is left out rather than
/// reported as nothing, and so is one every filter rejected.
/// `name` is the AES implementation the section is headed with, and
/// `implementation` is what the modes in it are built on: the engine
/// written for the same instructions where there is one, and the
/// portable construction over this cipher where there is not. A mode
/// with nothing for either is left out of the section rather than
/// measured twice under two names.
fn section<A, B>(
    name: &str,
    implementation: Implementation,
    options: &Options,
) -> bool
where
    A: BlockCipher<Block = [u8; 16], Key = Key<[u8; 16]>>,
    B: BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>,
{
    let wanted: Vec<&'static str> = ALGORITHMS
        .iter()
        .copied()
        .filter(|row| options.wants(name, row))
        .collect();
    if wanted.is_empty() {
        return false;
    }

    let mut keys = match Keys::<A, B>::try_new(implementation) {
        Ok(keys) => keys,
        // No such instructions here.
        Err(Error::NotSupported) => return false,
        Err(e) => {
            eprintln!("speed: {name}: {e}");
            return false;
        }
    };
    let mut tasks = keys.tasks();
    tasks.retain(|(row, _)| wanted.contains(row));
    if tasks.is_empty() {
        return false;
    }

    println!("\n{name}");
    println!("{}", heading());
    for (row_name, operation) in &mut tasks {
        println!("{}", row(row_name, operation, options.budget));
    }
    true
}

/// The hash rows: each family, and HMAC over it.
const HASHES: [&str; 4] =
    ["sha-256", "sha-512", "hmac-sha-256", "hmac-sha-512"];

/// Measures one pair of hash implementations, one per family,
/// returning whether it ran anything. A family the processor cannot
/// run is left out, as with the ciphers; on x86-64 the SHA-NI
/// section pairs its SHA-256 with the portable SHA-512, there being
/// no instruction for the latter.
fn hash_section<S256, S512>(
    implementation: &str,
    options: &Options,
    start256: fn() -> Result<S256, Error>,
    start512: fn() -> Result<S512, Error>,
) -> bool
where
    S256: Hash<Output = [u8; 32]> + Clone + BlockType,
    S512: Hash<Output = [u8; 64]> + Clone + BlockType,
{
    let wanted: Vec<&'static str> = HASHES
        .iter()
        .copied()
        .filter(|name| options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let (mut sha256, mut sha512) = match (start256(), start512()) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(Error::NotSupported), _) | (_, Err(Error::NotSupported)) => {
            return false;
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    // Keyed from a fresh hash of the same implementation, so the
    // HMAC rows measure the backend this section names.
    let mut hmac256 = Hmac::with(sha256.clone(), &KEY128);
    let mut hmac512 = Hmac::with(sha512.clone(), &KEY128);
    let mut tasks: Vec<Task<'_>> = vec![
        (
            "sha-256",
            Box::new(|d: &mut [u8]| {
                sha256.reset();
                sha256.update(d);
                black_box(sha256.finalize());
            }) as Operation<'_>,
        ),
        (
            "sha-512",
            Box::new(|d: &mut [u8]| {
                sha512.reset();
                sha512.update(d);
                black_box(sha512.finalize());
            }),
        ),
        (
            "hmac-sha-256",
            Box::new(|d: &mut [u8]| {
                hmac256.restart();
                hmac256.append(d);
                black_box(hmac256.tag());
            }),
        ),
        (
            "hmac-sha-512",
            Box::new(|d: &mut [u8]| {
                hmac512.restart();
                hmac512.append(d);
                black_box(hmac512.tag());
            }),
        ),
    ];
    tasks.retain(|(name, _)| wanted.contains(name));

    println!("\n{implementation}");
    println!("{}", heading());
    for (name, operation) in &mut tasks {
        println!("{}", row(name, operation, options.budget));
    }
    true
}

/// The SHA-3 rows: two digests and one extendable-output function,
/// the last squeezing 32 bytes.
/// The ChaCha20 row. What is built on it dispatches inside itself,
/// so those rows are in [`DISPATCHING`] instead.
const CHACHA: [&str; 1] = ["chacha20"];

/// What the ChaCha20 rows need of an implementation: the automatic
/// type and the per-backend types have the same methods but no
/// shared trait, since only the bench wants one.
trait StreamCipher: Sized {
    fn try_new(key: &Key<[u8; 32]>) -> Result<Self, Error>;
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error>;
}

impl StreamCipher for chacha20::ChaCha20 {
    fn try_new(key: &Key<[u8; 32]>) -> Result<Self, Error> {
        Ok(chacha20::ChaCha20::new(key))
    }
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        chacha20::ChaCha20::encrypt(self, nonce, counter, data)
    }
}

impl<B: chacha20::Backend> StreamCipher for chacha20::Cipher<B> {
    fn try_new(key: &Key<[u8; 32]>) -> Result<Self, Error> {
        chacha20::Cipher::try_new(key)
    }
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        chacha20::Cipher::encrypt(self, nonce, counter, data)
    }
}

/// Measures one ChaCha20 implementation, with Poly1305 and the AEAD
/// rows when `whole` says so; an implementation the processor cannot
/// run is left out.
fn chacha_section<C: StreamCipher>(
    implementation: &str,
    options: &Options,
) -> bool {
    let wanted: Vec<&'static str> = CHACHA
        .iter()
        .copied()
        .filter(|name| options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let cipher = match C::try_new(&Key::from(KEY256)) {
        Ok(cipher) => cipher,
        Err(Error::NotSupported) => return false,
        Err(e) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    let mut tasks: Vec<Task<'_>> = vec![(
        "chacha20",
        Box::new(|d: &mut [u8]| {
            let _ = cipher.encrypt(&NONCE, 1, d);
        }) as Operation<'_>,
    )];
    tasks.retain(|(name, _)| wanted.contains(name));

    println!("\n{implementation}");
    println!("{}", heading());
    for (name, operation) in &mut tasks {
        println!("{}", row(name, operation, options.budget));
    }
    true
}

const SHA3: [&str; 4] = ["sha3-256", "sha3-512", "shake128", "shake256"];

/// Measures one implementation of SHA-3, returning whether it ran
/// anything; an implementation the processor cannot run is left out.
#[allow(clippy::type_complexity)]
fn sha3_section<D256, D512, X128, X256>(
    implementation: &str,
    options: &Options,
    starts: (
        fn() -> Result<D256, Error>,
        fn() -> Result<D512, Error>,
        fn() -> Result<X128, Error>,
        fn() -> Result<X256, Error>,
    ),
) -> bool
where
    D256: Hash<Output = [u8; 32]>,
    D512: Hash<Output = [u8; 64]>,
    X128: Xof,
    X256: Xof,
{
    let wanted: Vec<&'static str> = SHA3
        .iter()
        .copied()
        .filter(|name| options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let states = (starts.0(), starts.1(), starts.2(), starts.3());
    let (mut d256, mut d512, mut x128, mut x256) = match states {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
        (Err(Error::NotSupported), _, _, _)
        | (_, Err(Error::NotSupported), _, _)
        | (_, _, Err(Error::NotSupported), _)
        | (_, _, _, Err(Error::NotSupported)) => return false,
        (Err(e), _, _, _)
        | (_, Err(e), _, _)
        | (_, _, Err(e), _)
        | (_, _, _, Err(e)) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    let mut tasks: Vec<Task<'_>> = vec![
        (
            "sha3-256",
            Box::new(|d: &mut [u8]| {
                d256.reset();
                d256.update(d);
                black_box(d256.finalize());
            }) as Operation<'_>,
        ),
        (
            "sha3-512",
            Box::new(|d: &mut [u8]| {
                d512.reset();
                d512.update(d);
                black_box(d512.finalize());
            }),
        ),
        (
            "shake128",
            Box::new(|d: &mut [u8]| {
                x128.reset();
                x128.update(d);
                let mut out = [0u8; 32];
                x128.finalize_xof().squeeze(&mut out);
                black_box(out);
            }),
        ),
        (
            "shake256",
            Box::new(|d: &mut [u8]| {
                x256.reset();
                x256.update(d);
                let mut out = [0u8; 32];
                x256.finalize_xof().squeeze(&mut out);
                black_box(out);
            }),
        ),
    ];
    tasks.retain(|(name, _)| wanted.contains(name));

    println!("\n{implementation}");
    println!("{}", heading());
    for (name, operation) in &mut tasks {
        println!("{}", row(name, operation, options.budget));
    }
    true
}

/// The rows whose implementation is settled inside them and cannot
/// be named from out here: SHA-1 picks its own, the generator builds
/// its own cipher, and Poly1305 and the AEAD over ChaCha20 each take
/// the best the processor has without being asked.
const DISPATCHING: [&str; 6] = [
    "sha-1",
    "ctr-drbg",
    "poly1305",
    "kmac128",
    "chacha20-poly1305-enc",
    "chacha20-poly1305-dec",
];

/// Measures them, returning whether it ran anything.
fn single_section(options: &Options) -> bool {
    let wanted: Vec<&'static str> = DISPATCHING
        .iter()
        .copied()
        .filter(|name| options.wants("dispatching", name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let mut sha1 = Sha1::new();
    // Seeded rather than drawn, so a run repeats and no entropy
    // source is needed for a measurement.
    let Ok(mut rng) = CtrDrbg::from_seed(&[0x5au8; 64]) else {
        return false;
    };
    // Neither of these can fail to build: the key is the right width
    // and the automatic ChaCha20 always exists.
    let mut mac = Poly1305::new(&Key::from(KEY256));
    let aead = ChaCha20Poly1305::new(&Key::from(KEY256));
    let mut kmac = Kmac128::new(&KEY256, b"");
    let mut tags = [[0u8; 16]; 2];
    let (enc_tag, dec_tag) = tags.split_at_mut(1);
    let mut tasks: Vec<Task<'_>> = vec![
        (
            "sha-1",
            Box::new(|d: &mut [u8]| {
                sha1.reset();
                sha1.update(d);
                black_box(sha1.finalize());
            }) as Operation<'_>,
        ),
        (
            "ctr-drbg",
            Box::new(|d: &mut [u8]| {
                let _ = rng.fill(d);
            }),
        ),
        (
            "poly1305",
            Box::new(|d: &mut [u8]| {
                mac.reset();
                mac.update(d);
                black_box(mac.finalize());
            }),
        ),
        (
            "kmac128",
            Box::new(|d: &mut [u8]| {
                kmac.update(d);
                black_box(Mac::finalize(&mut kmac));
            }),
        ),
        (
            "chacha20-poly1305-enc",
            Box::new(|d: &mut [u8]| {
                let _ = aead.encrypt(&NONCE, &[], d, &mut enc_tag[0]);
            }),
        ),
        // The tag never matches after the first round, which costs a
        // comparison and changes nothing else; the streaming form
        // keeps the wipe on a bad tag out of the measurement.
        (
            "chacha20-poly1305-dec",
            Box::new(|d: &mut [u8]| {
                let Ok(mut state) = aead.decryptor(&NONCE) else {
                    return;
                };
                let _ = state.update(d);
                let _ = state.verify(&dec_tag[0]);
            }),
        ),
    ];
    tasks.retain(|(name, _)| wanted.contains(name));

    println!("\ndispatching");
    println!("{}", heading());
    for (name, operation) in &mut tasks {
        println!("{}", row(name, operation, options.budget));
    }
    true
}

// Operations whose cost is the call rather than a rate over a
// buffer: everything with a key pair, the two password and key
// derivations, and the format-preserving modes, which work on a
// string of symbols rather than on bytes.

/// One such operation.
type Once<'a> = Box<dyn FnMut() + 'a>;

/// A named one.
type Job<'a> = (&'static str, Once<'a>);

/// The message every signature row signs. Short, because what these
/// rows measure is the key operation and not the hash in front of
/// it.
const MESSAGE: &[u8] = b"scytale benchmark message";

/// PBKDF2 is meant to be slow, and its cost is the iteration count;
/// this is the round number nearest what a login path would use.
const ITERATIONS: u32 = 100_000;

/// The digits a format-preserving row encrypts: a card number's
/// worth, which is what the modes are for.
const DIGITS: usize = 16;

/// FF3-1's tweak is exactly seven bytes.
const FF3_TWEAK: [u8; 7] = [0x3c; 7];

/// A generator seeded rather than drawn, so that every key below is
/// the same one on every run.
fn seeded() -> Result<CtrDrbg<crate::random::entropy::External>, Error> {
    CtrDrbg::from_seed(&[0x5au8; 64])
}

/// Whether the heading over the operation groups has been printed;
/// the first group to run prints it, so a run filtered down to the
/// throughput rows does not carry a heading over nothing.
static OPS_HEADING: AtomicBool = AtomicBool::new(false);

/// Prints one group of operations, returning whether it ran any.
/// The jobs are built by the caller, which has already made the keys
/// they close over.
fn ops_section(title: &str, jobs: Vec<Job<'_>>, options: &Options) -> bool {
    let mut jobs: Vec<Job<'_>> = jobs
        .into_iter()
        .filter(|(name, _)| options.wants(title, name))
        .collect();
    if jobs.is_empty() {
        return false;
    }
    if !OPS_HEADING.swap(true, Ordering::Relaxed) {
        println!("\nOperations a second, and the time one takes.");
    }
    println!("\n{title}");
    for (name, call) in &mut jobs {
        println!("{}", ops_row(name, call, options.budget));
    }
    true
}

/// Whether any of `names` is wanted, so that a group can be skipped
/// before its keys are made.
fn any_wanted(title: &str, names: &[&str], options: &Options) -> bool {
    names.iter().any(|name| options.wants(title, name))
}

/// One row: the name, how many of the operation run in a second, and
/// how long one takes.
fn ops_row(name: &str, call: &mut Once<'_>, budget: Duration) -> String {
    match ops_rate(call, budget) {
        Some(rate) if rate > 0.0 => {
            format!("  {name:28}{rate:>12.1}{:>12}", per_call(1.0 / rate))
        }
        _ => format!("  {name:28}{:>12}{:>12}", "-", "-"),
    }
}

/// Operations a second, calibrated and timed as [`rate`] does, but
/// with no buffer to hand the operation.
fn ops_rate(call: &mut Once<'_>, budget: Duration) -> Option<f64> {
    let mut once = |batch: u64| -> Duration {
        time_calls(batch, call).unwrap_or(Duration::from_secs(1))
    };
    let batch = calibrate(CALIBRATION, &mut once);

    let mut iterations: u64 = 0;
    let mut elapsed = Duration::ZERO;
    while elapsed < budget {
        elapsed += time_calls(batch, call)?;
        iterations = iterations.saturating_add(batch);
    }
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return None;
    }
    Some(iterations as f64 / seconds)
}

/// Runs `batch` calls and returns the CPU time they took.
fn time_calls(batch: u64, call: &mut Once<'_>) -> Option<Duration> {
    let start = ThreadTime::try_now().ok()?;
    for _ in 0..batch {
        call();
    }
    start.try_elapsed().ok()
}

/// A duration in the unit that shows it best.
fn per_call(seconds: f64) -> String {
    if seconds >= 1.0 {
        format!("{seconds:.2} s")
    } else if seconds >= 1e-3 {
        format!("{:.2} ms", seconds * 1e3)
    } else {
        format!("{:.2} us", seconds * 1e6)
    }
}

const KDF_JOBS: [&str; 4] = [
    "hkdf-sha-256",
    "hkdf-sha-512",
    "pbkdf2-sha-256",
    "pbkdf2-sha-512",
];

/// Key derivation: one derivation of a 32-byte key, which is what a
/// caller asks for. HKDF's cost is two hashes of a short input;
/// PBKDF2's is its iteration count, and nothing else.
fn kdf_ops(options: &Options) -> bool {
    if !any_wanted("kdf", &KDF_JOBS, options) {
        return false;
    }
    let jobs: Vec<Job<'_>> = vec![
        (
            "hkdf-sha-256",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = hkdf::derive::<sha2::Sha256>(
                    &KEY128,
                    &KEY256,
                    &[],
                    &mut out,
                );
                black_box(out);
            }) as Once<'_>,
        ),
        (
            "hkdf-sha-512",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = hkdf::derive::<sha2::Sha512>(
                    &KEY128,
                    &KEY256,
                    &[],
                    &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "pbkdf2-sha-256",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = pbkdf2::pbkdf2::<sha2::Sha256>(
                    &KEY128, &KEY128, ITERATIONS, &mut out,
                );
                black_box(out);
            }),
        ),
        (
            "pbkdf2-sha-512",
            Box::new(|| {
                let mut out = [0u8; 32];
                let _ = pbkdf2::pbkdf2::<sha2::Sha512>(
                    &KEY128, &KEY128, ITERATIONS, &mut out,
                );
                black_box(out);
            }),
        ),
    ];
    ops_section("kdf", jobs, options)
}

const KEX_JOBS: [&str; 8] = [
    "x25519-keygen",
    "x25519-agree",
    "ecdh-p256-keygen",
    "ecdh-p256-agree",
    "ecdh-p384-keygen",
    "ecdh-p384-agree",
    "ecdh-p521-keygen",
    "ecdh-p521-agree",
];

/// Key agreement: deriving a public key from a secret, and the
/// shared secret from a peer's.
fn kex_ops(options: &Options) -> bool {
    if !any_wanted("kex", &KEX_JOBS, options) {
        return false;
    }
    // A generator each, since two rows draw at once and one
    // borrow of each is all a closure can hold.
    let (Ok(mut build), Ok(mut rng256), Ok(mut rng384), Ok(mut rng521)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let secret = KEY256;
    let peer = x25519::public_key(&secret);
    let (Ok(p256), Ok(p256_peer), Ok(p384), Ok(p384_peer)) = (
        ecdh::p256::PrivateKey::generate(&mut build),
        ecdh::p256::PrivateKey::generate(&mut build),
        ecdh::p384::PrivateKey::generate(&mut build),
        ecdh::p384::PrivateKey::generate(&mut build),
    ) else {
        return false;
    };
    let (Ok(p521), Ok(p521_peer)) = (
        ecdh::p521::PrivateKey::generate(&mut build),
        ecdh::p521::PrivateKey::generate(&mut build),
    ) else {
        return false;
    };
    let p256_public = p256_peer.public_key();
    let p384_public = p384_peer.public_key();
    let p521_public = p521_peer.public_key();
    let jobs: Vec<Job<'_>> = vec![
        (
            "x25519-keygen",
            Box::new(|| {
                black_box(x25519::public_key(&secret));
            }) as Once<'_>,
        ),
        (
            "x25519-agree",
            Box::new(|| {
                black_box(x25519::shared_secret(&secret, &peer)).ok();
            }),
        ),
        (
            "ecdh-p256-keygen",
            Box::new(|| {
                black_box(ecdh::p256::PrivateKey::generate(&mut rng256)).ok();
            }),
        ),
        (
            "ecdh-p256-agree",
            Box::new(|| {
                black_box(p256.shared_secret(p256_public));
            }),
        ),
        (
            "ecdh-p384-keygen",
            Box::new(|| {
                black_box(ecdh::p384::PrivateKey::generate(&mut rng384)).ok();
            }),
        ),
        (
            "ecdh-p384-agree",
            Box::new(|| {
                black_box(p384.shared_secret(p384_public));
            }),
        ),
        (
            "ecdh-p521-keygen",
            Box::new(|| {
                black_box(ecdh::p521::PrivateKey::generate(&mut rng521)).ok();
            }),
        ),
        (
            "ecdh-p521-agree",
            Box::new(|| {
                black_box(p521.shared_secret(p521_public));
            }),
        ),
    ];
    ops_section("kex", jobs, options)
}

const SIG_JOBS: [&str; 14] = [
    "ed25519-keygen",
    "ed25519-sign",
    "ed25519-verify",
    "ecdsa-p256-keygen",
    "ecdsa-p256-sign",
    "ecdsa-p256-verify",
    "ecdsa-p384-keygen",
    "ecdsa-p384-sign",
    "ecdsa-p384-verify",
    "ecdsa-p521-keygen",
    "ecdsa-p521-sign",
    "ecdsa-p521-verify",
    "rsa-2048-pss-sign",
    "rsa-2048-pss-verify",
];

/// The signature schemes with a classical hardness assumption.
/// Signing dominates for RSA and verification for the curves, which
/// is the whole shape of the choice between them.
fn sig_ops(options: &Options) -> bool {
    if !any_wanted("sig", &SIG_JOBS, options) {
        return false;
    }
    let (Ok(mut build), Ok(mut rng256), Ok(mut rng384), Ok(mut rng521)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let ed_secret = KEY256;
    let ed_key = ed25519::PrivateKey::new(&Key::from(ed_secret));
    let ed_public = ed_key.public_key().bytes();
    let ed_signature = ed_key.sign(MESSAGE);
    let (Ok(p256), Ok(p384), Ok(p521)) = (
        ecdsa::p256::PrivateKey::generate(&mut build),
        ecdsa::p384::PrivateKey::generate(&mut build),
        ecdsa::p521::PrivateKey::generate(&mut build),
    ) else {
        return false;
    };
    let (Ok(sig256), Ok(sig384), Ok(sig521)) = (
        p256.sign::<sha2::Sha256>(MESSAGE),
        p384.sign::<sha2::Sha384>(MESSAGE),
        p521.sign::<sha2::Sha512>(MESSAGE),
    ) else {
        return false;
    };
    let Ok(rsa_key) = rsa::PrivateKey::generate(&mut build, 2048) else {
        return false;
    };
    let Ok(rsa_signature) =
        rsa_key.sign_pss_with_salt::<sha2::Sha256>(MESSAGE, &KEY256)
    else {
        return false;
    };
    let jobs: Vec<Job<'_>> = vec![
        (
            "ed25519-keygen",
            Box::new(|| {
                black_box(ed25519::public_key(&ed_secret));
            }) as Once<'_>,
        ),
        (
            "ed25519-sign",
            Box::new(|| {
                black_box(ed_key.sign(MESSAGE));
            }),
        ),
        (
            "ed25519-verify",
            Box::new(|| {
                black_box(ed25519::verify(&ed_public, MESSAGE, &ed_signature))
                    .ok();
            }),
        ),
        (
            "ecdsa-p256-keygen",
            Box::new(|| {
                black_box(ecdsa::p256::PrivateKey::generate(&mut rng256)).ok();
            }),
        ),
        (
            "ecdsa-p256-sign",
            Box::new(|| {
                black_box(p256.sign::<sha2::Sha256>(MESSAGE)).ok();
            }),
        ),
        (
            "ecdsa-p256-verify",
            Box::new(|| {
                black_box(
                    p256.public_key().verify::<sha2::Sha256>(MESSAGE, &sig256),
                )
                .ok();
            }),
        ),
        (
            "ecdsa-p384-keygen",
            Box::new(|| {
                black_box(ecdsa::p384::PrivateKey::generate(&mut rng384)).ok();
            }),
        ),
        (
            "ecdsa-p384-sign",
            Box::new(|| {
                black_box(p384.sign::<sha2::Sha384>(MESSAGE)).ok();
            }),
        ),
        (
            "ecdsa-p384-verify",
            Box::new(|| {
                black_box(
                    p384.public_key().verify::<sha2::Sha384>(MESSAGE, &sig384),
                )
                .ok();
            }),
        ),
        (
            "ecdsa-p521-keygen",
            Box::new(|| {
                black_box(ecdsa::p521::PrivateKey::generate(&mut rng521)).ok();
            }),
        ),
        (
            "ecdsa-p521-sign",
            Box::new(|| {
                black_box(p521.sign::<sha2::Sha512>(MESSAGE)).ok();
            }),
        ),
        (
            "ecdsa-p521-verify",
            Box::new(|| {
                black_box(
                    p521.public_key().verify::<sha2::Sha512>(MESSAGE, &sig521),
                )
                .ok();
            }),
        ),
        (
            "rsa-2048-pss-sign",
            Box::new(|| {
                black_box(
                    rsa_key
                        .sign_pss_with_salt::<sha2::Sha256>(MESSAGE, &KEY256),
                )
                .ok();
            }),
        ),
        (
            "rsa-2048-pss-verify",
            Box::new(|| {
                black_box(
                    rsa_key
                        .public_key()
                        .verify_pss_with_salt_len::<sha2::Sha256>(
                            MESSAGE,
                            rsa_signature.as_ref(),
                            KEY256.len(),
                        ),
                )
                .ok();
            }),
        ),
    ];
    ops_section("sig", jobs, options)
}

/// A post-quantum signing key and one signature from it, bound in
/// the caller's scope so that the rows below can share them. Keys
/// are bound before the job list, since the closures borrow them.
macro_rules! pq_sig_key {
    ($key:ident, $signature:ident, $build:expr, $private:ty) => {
        let Ok($key) = <$private>::generate($build) else {
            return false;
        };
        let Ok($signature) = $key.sign_deterministic(&[], MESSAGE) else {
            return false;
        };
    };
}

/// The three rows for one parameter set.
macro_rules! pq_sig_rows {
    ($jobs:expr, $key:ident, $signature:ident, $rng:expr, $private:ty,
     $name:literal) => {
        $jobs.push((
            concat!($name, "-keygen"),
            Box::new(|| {
                black_box(<$private>::generate($rng)).ok();
            }) as Once<'_>,
        ));
        $jobs.push((
            concat!($name, "-sign"),
            Box::new(|| {
                black_box($key.sign_deterministic(&[], MESSAGE)).ok();
            }),
        ));
        $jobs.push((
            concat!($name, "-verify"),
            Box::new(|| {
                black_box($key.public_key().verify(&[], MESSAGE, &$signature))
                    .ok();
            }),
        ));
    };
}

const PQ_SIG_JOBS: [&str; 5] = [
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-128f",
];

/// The post-quantum signature schemes. Signing is measured in its
/// deterministic form, which is the same work as the hedged one
/// without a draw from the generator in the middle of it. SLH-DSA
/// has twelve parameter sets; the two here are the small and the
/// fast end of the 128-bit ones, and the rest fall between the
/// pattern they show.
fn pq_sig_ops(options: &Options) -> bool {
    if !PQ_SIG_JOBS
        .iter()
        .any(|name| any_wanted("sig-pq", &[name], options))
    {
        return false;
    }
    let (Ok(mut build), Ok(mut r1), Ok(mut r2), Ok(mut r3)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let (Ok(mut r4), Ok(mut r5)) = (seeded(), seeded()) else {
        return false;
    };
    pq_sig_key!(
        mldsa44,
        mldsa44_sig,
        &mut build,
        crate::sig::ml_dsa::ml_dsa_44::PrivateKey
    );
    pq_sig_key!(
        mldsa65,
        mldsa65_sig,
        &mut build,
        crate::sig::ml_dsa::ml_dsa_65::PrivateKey
    );
    pq_sig_key!(
        mldsa87,
        mldsa87_sig,
        &mut build,
        crate::sig::ml_dsa::ml_dsa_87::PrivateKey
    );
    pq_sig_key!(
        slh128s,
        slh128s_sig,
        &mut build,
        crate::sig::slh_dsa::sha2_128s::PrivateKey
    );
    pq_sig_key!(
        slh128f,
        slh128f_sig,
        &mut build,
        crate::sig::slh_dsa::sha2_128f::PrivateKey
    );
    let mut jobs: Vec<Job<'_>> = Vec::new();
    pq_sig_rows!(
        jobs,
        mldsa44,
        mldsa44_sig,
        &mut r1,
        crate::sig::ml_dsa::ml_dsa_44::PrivateKey,
        "ml-dsa-44"
    );
    pq_sig_rows!(
        jobs,
        mldsa65,
        mldsa65_sig,
        &mut r2,
        crate::sig::ml_dsa::ml_dsa_65::PrivateKey,
        "ml-dsa-65"
    );
    pq_sig_rows!(
        jobs,
        mldsa87,
        mldsa87_sig,
        &mut r3,
        crate::sig::ml_dsa::ml_dsa_87::PrivateKey,
        "ml-dsa-87"
    );
    pq_sig_rows!(
        jobs,
        slh128s,
        slh128s_sig,
        &mut r4,
        crate::sig::slh_dsa::sha2_128s::PrivateKey,
        "slh-dsa-sha2-128s"
    );
    pq_sig_rows!(
        jobs,
        slh128f,
        slh128f_sig,
        &mut r5,
        crate::sig::slh_dsa::sha2_128f::PrivateKey,
        "slh-dsa-sha2-128f"
    );
    ops_section("sig-pq", jobs, options)
}

/// An ML-KEM key and one ciphertext under it, likewise.
macro_rules! kem_key {
    ($key:ident, $ciphertext:ident, $build:expr, $private:ty) => {
        let Ok($key) = <$private>::generate($build) else {
            return false;
        };
        let Ok(($ciphertext, _)) = $key.public_key().encapsulate($build) else {
            return false;
        };
    };
}

/// The three rows for one parameter set.
macro_rules! kem_rows {
    ($jobs:expr, $key:ident, $ciphertext:ident, $keygen:expr, $encap:expr,
     $private:ty, $name:literal) => {
        $jobs.push((
            concat!($name, "-keygen"),
            Box::new(|| {
                black_box(<$private>::generate($keygen)).ok();
            }) as Once<'_>,
        ));
        $jobs.push((
            concat!($name, "-encapsulate"),
            Box::new(|| {
                black_box($key.public_key().encapsulate($encap)).ok();
            }),
        ));
        $jobs.push((
            concat!($name, "-decapsulate"),
            Box::new(|| {
                black_box($key.decapsulate(&$ciphertext));
            }),
        ));
    };
}

const KEM_JOBS: [&str; 3] = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"];

/// Key encapsulation, the three parameter sets.
fn kem_ops(options: &Options) -> bool {
    if !KEM_JOBS
        .iter()
        .any(|name| any_wanted("kem", &[name], options))
    {
        return false;
    }
    let (Ok(mut build), Ok(mut k1), Ok(mut e1), Ok(mut k2)) =
        (seeded(), seeded(), seeded(), seeded())
    else {
        return false;
    };
    let (Ok(mut e2), Ok(mut k3), Ok(mut e3)) = (seeded(), seeded(), seeded())
    else {
        return false;
    };
    kem_key!(
        kem512,
        kem512_ct,
        &mut build,
        crate::kem::ml_kem::ml_kem_512::PrivateKey
    );
    kem_key!(
        kem768,
        kem768_ct,
        &mut build,
        crate::kem::ml_kem::ml_kem_768::PrivateKey
    );
    kem_key!(
        kem1024,
        kem1024_ct,
        &mut build,
        crate::kem::ml_kem::ml_kem_1024::PrivateKey
    );
    let mut jobs: Vec<Job<'_>> = Vec::new();
    kem_rows!(
        jobs,
        kem512,
        kem512_ct,
        &mut k1,
        &mut e1,
        crate::kem::ml_kem::ml_kem_512::PrivateKey,
        "ml-kem-512"
    );
    kem_rows!(
        jobs,
        kem768,
        kem768_ct,
        &mut k2,
        &mut e2,
        crate::kem::ml_kem::ml_kem_768::PrivateKey,
        "ml-kem-768"
    );
    kem_rows!(
        jobs,
        kem1024,
        kem1024_ct,
        &mut k3,
        &mut e3,
        crate::kem::ml_kem::ml_kem_1024::PrivateKey,
        "ml-kem-1024"
    );
    ops_section("kem", jobs, options)
}

const PKE_JOBS: [&str; 2] = ["rsa-2048-oaep-encrypt", "rsa-2048-oaep-decrypt"];

/// Public-key encryption. The encryption key is a different type
/// from the signing one, since a key does one job.
fn pke_ops(options: &Options) -> bool {
    if !any_wanted("pke", &PKE_JOBS, options) {
        return false;
    }
    let (Ok(mut build), Ok(mut rng)) = (seeded(), seeded()) else {
        return false;
    };
    let Ok(key) = oaep::PrivateKey::generate(&mut build, 2048) else {
        return false;
    };
    let Ok(ciphertext) = key.public_key().encrypt_oaep::<sha2::Sha256, _>(
        &mut build,
        &[],
        MESSAGE,
    ) else {
        return false;
    };
    let jobs: Vec<Job<'_>> = vec![
        (
            "rsa-2048-oaep-encrypt",
            Box::new(|| {
                black_box(key.public_key().encrypt_oaep::<sha2::Sha256, _>(
                    &mut rng,
                    &[],
                    MESSAGE,
                ))
                .ok();
            }) as Once<'_>,
        ),
        (
            "rsa-2048-oaep-decrypt",
            Box::new(|| {
                let mut out = [0u8; 256];
                black_box(key.decrypt_oaep::<sha2::Sha256>(
                    &[],
                    ciphertext.as_ref(),
                    &mut out,
                ))
                .ok();
            }),
        ),
    ];
    ops_section("pke", jobs, options)
}

const FPE_JOBS: [&str; 2] = ["ff1-radix10", "ff3-1-radix10"];

/// The format-preserving modes, which work on a string of symbols
/// rather than on bytes: sixteen decimal digits, a card number's
/// worth, which is what they exist for.
fn fpe_ops(options: &Options) -> bool {
    if !any_wanted("fpe", &FPE_JOBS, options) {
        return false;
    }
    let (Ok(ff1), Ok(ff3)) = (
        Ff1::<aes::Aes<16>>::try_new(&Key::from(KEY128), 10),
        Ff3_1::<aes::Aes<16>>::try_new(&Key::from(KEY128), 10),
    ) else {
        return false;
    };
    let mut digits = [0u16; DIGITS];
    for (i, d) in digits.iter_mut().enumerate() {
        *d = (i % 10) as u16;
    }
    let mut ff1_digits = digits;
    let mut ff3_digits = digits;
    let jobs: Vec<Job<'_>> = vec![
        (
            "ff1-radix10",
            Box::new(move || {
                let _ = ff1.encrypt(&[], &mut ff1_digits);
                black_box(&ff1_digits);
            }) as Once<'_>,
        ),
        (
            "ff3-1-radix10",
            Box::new(move || {
                let _ = ff3.encrypt(&FF3_TWEAK, &mut ff3_digits);
                black_box(&ff3_digits);
            }),
        ),
    ];
    ops_section("fpe", jobs, options)
}

/// The rows, in the order they are printed. Kept beside the tasks
/// they name so that a filter can be applied before any key is
/// expanded, which is what lets an unsupported implementation be
/// skipped silently.
const ALGORITHMS: [&str; 23] = [
    "aes-128-ecb-enc",
    "aes-128-ecb-dec",
    "aes-256-ecb-enc",
    "aes-128-cbc-enc",
    "aes-128-cbc-dec",
    "aes-128-cfb1-enc",
    "aes-128-cfb8-enc",
    "aes-128-cfb128-enc",
    "aes-128-ofb",
    "aes-128-ctr",
    "aes-256-ctr",
    "aes-128-gmac",
    "aes-128-gcm-enc",
    "aes-128-gcm-dec",
    "aes-256-gcm-enc",
    "aes-128-gcm-siv-enc",
    "aes-128-xpn-enc",
    "aes-128-ccm-enc",
    "aes-128-xts-enc",
    "aes-128-xts-dec",
    "aes-128-kw-wrap",
    "aes-128-kwp-wrap",
    "aes-128-cmac",
];

/// Everything an implementation's rows are built from, held together
/// so that the borrows in [`Keys::tasks`] all have one owner.
struct Keys<
    A: BlockCipher<Block = [u8; 16], Key = Key<[u8; 16]>>,
    B: BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>,
> {
    ecb128: A,
    ecb256: B,
    cbc: Option<Cbc<A>>,
    cfb1: Cfb1<A>,
    cfb8: Cfb8<A>,
    cfb128: Cfb128<A>,
    ofb: Ofb<A>,
    ctr: Option<Ctr<A>>,
    ctr256: Option<Ctr<B>>,
    gcm128: Option<Gcm<A>>,
    gcm256: Option<Gcm<B>>,
    siv: Option<GcmSiv<A>>,
    xpn: Option<Xpn<A>>,
    ccm: Option<Ccm<A>>,
    xts: Option<Xts<A>>,
    kw: Kw<A>,
    kwp: Kwp<A>,
    cmac: Cmac<A>,
    /// Room for a wrapped key, one buffer for each of the two rows
    /// that writes one: the largest input and the eight bytes of
    /// check value that go on the end of it.
    wrapped: [Vec<u8>; 2],
    /// A tag buffer for each row that writes one; separate buffers so
    /// the rows borrow disjointly.
    tags: [[u8; 16]; 6],
}

/// Key material. Fixed rather than drawn, so that a run repeats.
const KEY128: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,
];
const KEY256: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
/// XTS takes two keys, and they must differ.
const KEY_XTS_DATA: [u8; 16] = KEY128;
const KEY_XTS_TWEAK: [u8; 16] = [0x99; 16];
const NONCE: [u8; 12] = [0xa5; 12];
/// XPN builds its nonce from a salt and a frame number, both of
/// them the width of a short GCM nonce.
const SALT: [u8; 12] = [0x11; 12];
const IV: [u8; 16] = [0x5a; 16];
const TWEAK: [u8; 16] = [0x3c; 16];
/// The tag a decryption is checked against. It will not match after
/// the first iteration, which costs a comparison and changes nothing
/// else: the keystream and the hash are the same work either way, and
/// going through the streaming type rather than `Gcm::decrypt` keeps
/// the wipe on a bad tag out of the measurement.
const CHECKED_TAG: [u8; 16] = [0; 16];

impl<A, B> Keys<A, B>
where
    A: BlockCipher<Block = [u8; 16], Key = Key<[u8; 16]>>,
    B: BlockCipher<Block = [u8; 16], Key = Key<[u8; 32]>>,
{
    /// The keys for one implementation.
    ///
    /// A mode written out for particular instructions is built on
    /// those and no others, so that a row appears under the name of
    /// the code that ran it. Where a mode has nothing written for
    /// them it yields `None`, and its rows are left out of the
    /// section rather than filled in with something else.
    fn try_new(implementation: Implementation) -> Result<Self, Error> {
        let k128 = Key::from(KEY128);
        let k256 = Key::from(KEY256);
        Ok(Keys {
            ecb128: A::new(&k128),
            ecb256: B::new(&k256),
            cbc: Cbc::with_implementation(&k128, implementation),
            cfb1: Cfb1::new(&k128),
            cfb8: Cfb8::new(&k128),
            cfb128: Cfb128::new(&k128),
            ofb: Ofb::new(&k128),
            ctr: Ctr::with_implementation(&k128, implementation),
            ctr256: Ctr::with_implementation(&k256, implementation),
            gcm128: Gcm::with_implementation(&k128, implementation),
            gcm256: Gcm::with_implementation(&k256, implementation),
            siv: GcmSiv::with_implementation(&k128, implementation),
            xpn: Xpn::with_implementation(&k128, implementation),
            ccm: Ccm::with_implementation(&k128, implementation),
            xts: Xts::with_implementation(
                &Key::from(KEY_XTS_DATA),
                &Key::from(KEY_XTS_TWEAK),
                implementation,
            ),
            kw: Kw::new(&k128),
            kwp: Kwp::new(&k128),
            cmac: Cmac::new(&k128),
            wrapped: [
                vec![0u8; SIZES[SIZES.len() - 1] + 8],
                vec![0u8; SIZES[SIZES.len() - 1] + 8],
            ],
            tags: [[0u8; 16]; 6],
        })
    }

    /// One closure per row. Results are discarded: every call here is
    /// given arguments it accepts, and a mode that started failing
    /// would show as an impossible rate rather than pass unnoticed.
    fn tasks(&mut self) -> Vec<Task<'_>> {
        let Keys {
            ecb128,
            ecb256,
            cbc,
            cfb1,
            cfb8,
            cfb128,
            ofb,
            ctr,
            ctr256,
            gcm128,
            gcm256,
            siv,
            xpn,
            ccm,
            xts,
            kw,
            kwp,
            cmac,
            wrapped,
            tags,
        } = self;
        // Split so that each row that writes a tag borrows its own.
        let (gmac_tag, tags) = tags.split_first_mut().expect("six tags");
        let (gcm_tag, tags) = tags.split_first_mut().expect("five tags");
        let (gcm256_tag, tags) = tags.split_first_mut().expect("four tags");
        let (siv_tag, tags) = tags.split_first_mut().expect("three tags");
        let (xpn_tag, tags) = tags.split_first_mut().expect("two tags");
        let (ccm_tag, _) = tags.split_first_mut().expect("one tag");
        let (kw_out, wrapped) = wrapped.split_first_mut().expect("two buffers");
        let (kwp_out, _) = wrapped.split_first_mut().expect("one buffer");
        let mut tasks: Vec<Task<'_>> = Vec::new();
        tasks.push((
            "aes-128-ecb-enc",
            Box::new(|d: &mut [u8]| {
                ecb128.encrypt(blocks_of(d));
            }) as Operation<'_>,
        ));
        tasks.push((
            "aes-128-ecb-dec",
            Box::new(|d: &mut [u8]| {
                ecb128.decrypt(blocks_of(d));
            }),
        ));
        tasks.push((
            "aes-256-ecb-enc",
            Box::new(|d: &mut [u8]| {
                ecb256.encrypt(blocks_of(d));
            }),
        ));
        if let Some(cbc) = cbc {
            tasks.push((
                "aes-128-cbc-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = cbc.encrypt(&IV, d);
                }),
            ));
            tasks.push((
                "aes-128-cbc-dec",
                Box::new(|d: &mut [u8]| {
                    let _ = cbc.decrypt(&IV, d);
                }),
            ));
        }
        // A bit at a time, which is what the mode is for and
        // why it is the slowest row here.
        tasks.push((
            "aes-128-cfb1-enc",
            Box::new(|d: &mut [u8]| {
                let bits = d.len() * 8;
                let _ = cfb1.encrypt(&IV, d, bits);
            }),
        ));
        tasks.push((
            "aes-128-cfb8-enc",
            Box::new(|d: &mut [u8]| {
                cfb8.encrypt(&IV, d);
            }),
        ));
        tasks.push((
            "aes-128-cfb128-enc",
            Box::new(|d: &mut [u8]| {
                let _ = cfb128.encrypt(&IV, d);
            }),
        ));
        tasks.push((
            "aes-128-ofb",
            Box::new(|d: &mut [u8]| {
                ofb.encrypt(&IV, d);
            }),
        ));
        if let Some(ctr) = ctr {
            tasks.push((
                "aes-128-ctr",
                Box::new(|d: &mut [u8]| {
                    ctr.encrypt(&IV, d);
                }),
            ));
        }
        if let Some(ctr256) = ctr256 {
            tasks.push((
                "aes-256-ctr",
                Box::new(|d: &mut [u8]| {
                    ctr256.encrypt(&IV, d);
                }),
            ));
        }
        if let Some(gcm128) = gcm128 {
            // The buffer is the additional data and the message is
            // empty, which is GHASH and nothing else.
            tasks.push((
                "aes-128-gmac",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm128.encrypt(&NONCE, d, &mut [], gmac_tag);
                }),
            ));
            tasks.push((
                "aes-128-gcm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm128.encrypt(&NONCE, &[], d, gcm_tag);
                }),
            ));
            tasks.push((
                "aes-128-gcm-dec",
                Box::new(|d: &mut [u8]| {
                    let Ok(mut state) = gcm128.decryptor(&NONCE) else {
                        return;
                    };
                    let _ = state.update(d);
                    let _ = state.verify(&CHECKED_TAG);
                }),
            ));
        }
        if let Some(gcm256) = gcm256 {
            tasks.push((
                "aes-256-gcm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm256.encrypt(&NONCE, &[], d, gcm256_tag);
                }),
            ));
        }
        if let Some(siv) = siv {
            tasks.push((
                "aes-128-gcm-siv-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = siv.encrypt(&NONCE, &[], d, siv_tag);
                }),
            ));
        }
        if let Some(xpn) = xpn {
            tasks.push((
                "aes-128-xpn-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = xpn.encrypt(&SALT, &NONCE, &[], d, xpn_tag);
                }),
            ));
        }
        if let Some(ccm) = ccm {
            tasks.push((
                "aes-128-ccm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = ccm.encrypt(&NONCE, &[], d, ccm_tag);
                }),
            ));
        }
        if let Some(xts) = xts {
            tasks.push((
                "aes-128-xts-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = xts.encrypt(&TWEAK, d);
                }),
            ));
            tasks.push((
                "aes-128-xts-dec",
                Box::new(|d: &mut [u8]| {
                    let _ = xts.decrypt(&TWEAK, d);
                }),
            ));
        }
        // Wrapping writes eight bytes more than it reads, so
        // these two write into a buffer of their own.
        tasks.push((
            "aes-128-kw-wrap",
            Box::new(|d: &mut [u8]| {
                let _ = kw.wrap(d, &mut kw_out[..d.len() + 8]);
            }),
        ));
        tasks.push((
            "aes-128-kwp-wrap",
            Box::new(|d: &mut [u8]| {
                let _ = kwp.wrap(d, &mut kwp_out[..d.len() + 8]);
            }),
        ));
        tasks.push((
            "aes-128-cmac",
            Box::new(|d: &mut [u8]| {
                cmac.update(d);
                black_box(cmac.finalize());
            }),
        ));
        tasks
    }
}

/// The whole blocks of `data`. Every size the benchmark uses is a
/// multiple of the block, so nothing is ever left over.
fn blocks_of(data: &mut [u8]) -> &mut [[u8; 16]] {
    let (blocks, rest) = data.as_chunks_mut::<16>();
    debug_assert!(rest.is_empty());
    blocks
}

/// The column headings, the buffer sizes.
fn heading() -> String {
    let mut line = format!("{:24}", "");
    for size in SIZES {
        let _ = write!(line, "{size:>9}");
    }
    line
}

/// One row: the name, then a rate for each size.
fn row(name: &str, operation: &mut Operation<'_>, budget: Duration) -> String {
    let mut line = format!("  {name:22}");
    for size in SIZES {
        match rate(operation, size, budget) {
            Some(bytes) => {
                let _ = write!(line, "{:>9.1}", bytes / 1e6);
            }
            // The clock refused, which is the same answer at every
            // size, so say so once per cell rather than give up.
            None => {
                let _ = write!(line, "{:>9}", "-");
            }
        }
    }
    line
}

/// Bytes a second for one operation at one size.
///
/// The clock is read once around a batch of iterations rather than
/// around each one, so its own cost is divided by the batch. The
/// batch is chosen first, by doubling until a batch lasts
/// [`CALIBRATION`], which also serves as the warm-up: by the time the
/// measurement starts the buffer is resident and the processor has
/// settled.
fn rate(
    operation: &mut Operation<'_>,
    size: usize,
    budget: Duration,
) -> Option<f64> {
    let mut buffer = pattern(size);
    let mut once = |batch: u64| -> Duration {
        time_batch(batch, &mut buffer, operation)
            .unwrap_or(Duration::from_secs(1))
    };
    let batch = calibrate(CALIBRATION, &mut once);

    let mut iterations: u64 = 0;
    let mut elapsed = Duration::ZERO;
    while elapsed < budget {
        elapsed += time_batch(batch, &mut buffer, operation)?;
        iterations = iterations.saturating_add(batch);
    }
    Some(throughput(iterations, size, elapsed))
}

/// Runs `batch` iterations and returns the CPU time they took, or
/// `None` where the clock is unavailable.
fn time_batch(
    batch: u64,
    buffer: &mut [u8],
    operation: &mut Operation<'_>,
) -> Option<Duration> {
    let start = ThreadTime::try_now().ok()?;
    for _ in 0..batch {
        // Hides the buffer from the optimiser going in and its
        // contents coming out. Without this a mode whose result is
        // discarded is dead code, and with the release profile's
        // link-time optimisation it would be removed.
        operation(black_box(buffer));
        black_box(&buffer);
    }
    start.try_elapsed().ok()
}

/// Chooses how many iterations to time at once: the smallest power of
/// two whose run reaches `target`.
///
/// Separated from the clock so it can be checked against a made-up
/// one. An operation too quick to reach the target within
/// [`MAX_BATCH`] stops there rather than doubling forever.
fn calibrate(target: Duration, mut once: impl FnMut(u64) -> Duration) -> u64 {
    let mut batch: u64 = 1;
    while batch < MAX_BATCH {
        if once(batch) >= target {
            break;
        }
        batch *= 2;
    }
    batch
}

/// Bytes a second, and zero rather than infinity where no time
/// passed, which is what a clock too coarse to see the work reports.
fn throughput(iterations: u64, size: usize, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    iterations as f64 * size as f64 / seconds
}

/// A buffer of `size` bytes, filled so that it is not all zeros.
/// Nothing measured here is data-dependent; this only keeps the
/// pages real and the contents recognisable in a debugger.
fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

/// Checks the parts of the harness that have an answer to be right
/// about, since a bench target with its own harness is never reached
/// by `cargo test`.
/// Checks the harness itself, and says whether it holds.
fn self_test() -> bool {
    let mut failures = Vec::new();
    let mut check = |name: &str, ok: bool| {
        if !ok {
            failures.push(name.to_string());
        }
    };

    // A fast operation calibrates upwards until a batch is long
    // enough, and a slow one stays at a single iteration.
    let fast = calibrate(Duration::from_millis(10), |batch| {
        Duration::from_nanos(batch)
    });
    check("calibrate reaches the target", fast >= 10_000_000);
    check("calibrate stops at the target", fast <= 20_000_000);
    let slow =
        calibrate(Duration::from_millis(10), |_| Duration::from_millis(50));
    check("calibrate leaves a slow operation alone", slow == 1);
    // One that never gets there stops rather than doubling forever.
    let never = calibrate(Duration::from_secs(1), |_| Duration::ZERO);
    check("calibrate gives up", never == MAX_BATCH);

    // A thousand iterations of a thousand bytes in a second.
    let rate = throughput(1000, 1000, Duration::from_secs(1));
    check("throughput counts bytes", (rate - 1e6).abs() < 1.0);
    check(
        "throughput survives a stopped clock",
        throughput(1000, 1000, Duration::ZERO) == 0.0,
    );

    // Filters are conjunctive and case-insensitive.
    let options =
        Options::parse(["GCM", "aesni"].into_iter().map(String::from))
            .ok()
            .flatten()
            .expect("filters parse");
    check(
        "both filters match",
        options.wants("aesni", "aes-128-gcm-enc"),
    );
    check(
        "one filter is not enough",
        !options.wants("vaes", "aes-128-gcm-enc"),
    );
    check(
        "a filter must appear",
        !options.wants("aesni", "aes-128-ctr"),
    );

    // Commas inside a word offer alternatives, so that two rows can
    // be asked for and compared within one run.
    let options =
        Options::parse(["aesni", "ctr,ecb-enc"].into_iter().map(String::from))
            .ok()
            .flatten()
            .expect("filters parse");
    check(
        "the first alternative matches",
        options.wants("aesni", "aes-128-ctr"),
    );
    check(
        "the second alternative matches",
        options.wants("aesni", "aes-128-ecb-enc"),
    );
    check(
        "neither alternative matches",
        !options.wants("aesni", "aes-128-ofb"),
    );
    check(
        "the other words still have to match",
        !options.wants("vaes", "aes-128-ctr"),
    );

    check(
        "--seconds is rejected when it is not a duration",
        Options::parse(["--seconds", "-1"].into_iter().map(String::from))
            .is_err(),
    );

    // Every named row is built, or a filter would silently drop it.
    let mut keys =
        Keys::<Ttable<16>, Ttable<32>>::try_new(Implementation::Portable)
            .expect("t-table keys");
    let built = keys.tasks();
    check(
        "every algorithm has a task",
        built.len() == ALGORITHMS.len(),
    );
    check(
        "the tasks are the algorithms, in order",
        built.iter().map(|(name, _)| *name).eq(ALGORITHMS),
    );

    // The layout has to hold: the checks above are worthless if the
    // table is unreadable.
    check("the heading fits 80 columns", heading().len() <= 80);

    if failures.is_empty() {
        println!("speed: self-test passed");
        return true;
    }
    for failure in &failures {
        eprintln!("speed: FAILED: {failure}");
    }
    false
}
