# scytale

[![CI][ci-badge]][ci]
[![crates.io][version-badge]][crate]
[![docs.rs][docs-badge]][docs]
[![MSRV][msrv-badge]][crate]
[![BSD-2-Clause][license-badge]][license]

[ci-badge]: https://github.com/6d7770/scytale/actions/workflows/ci.yml/badge.svg?branch=main
[ci]: https://github.com/6d7770/scytale/actions/workflows/ci.yml
[version-badge]: https://img.shields.io/crates/v/scytale.svg
[crate]: https://crates.io/crates/scytale
[docs-badge]: https://docs.rs/scytale/badge.svg
[docs]: https://docs.rs/scytale
[msrv-badge]: https://img.shields.io/crates/msrv/scytale.svg
[license-badge]: https://img.shields.io/crates/l/scytale.svg
[license]: https://github.com/6d7770/scytale/blob/main/LICENSE

Correct, fast, portable cryptography in Rust: ciphers, authenticated
encryption and the modes over them, hashes, message authentication,
key derivation, key agreement, public-key encryption, signatures,
post-quantum key encapsulation and signatures, and random numbers. It
is `no_std`, has two dependencies, needs no C compiler and no build
script, and has no feature flags to get wrong.

## The name

A [scytale][wiki] is a rod. The Spartans wound a strip of leather
around one and wrote the message along the rod, so that unwound the
strip carries a column of unrelated letters and reads again only when
it is wound on a rod of the same diameter. The key is a physical
dimension, and the ciphertext is a strip of leather a courier can
wear.

Whether it was ever really used to keep a secret is disputed: the
surviving accounts fit a device for proving that a message came from
whoever held the matching rod at least as well as they fit a cipher.
The earliest cryptographic instrument we have a name for may have
been a message authentication code.

Say it SKIT-uh-lee, to rhyme with Italy: that is what the
dictionaries give and what the author says.

The Greek is σκυτάλη, skutale, a staff or a baton, from σκύταλον,
skutalon, the same thing. An Athenian would have said it about
sku-TA-leh: the first vowel is the rounded one English lacks and
French writes as the u of tu, the last is a long open e, and the mark
over the alpha was a rise in pitch rather than a stress, so the word
lifted in the middle instead of leaning on it. It is still a living
word. In modern Greek, said skee-TAH-lee, a skutale is the baton a
relay runner hands to the next, which is very nearly where the
English ended up.

[wiki]: https://en.wikipedia.org/wiki/Scytale

## Status

Scytale is now a credible choice for a developer who needs
cryptography in Rust. It covers what many applications need, from
authenticated encryption to post-quantum signatures; it is checked
against every public vector set that exists for what it implements;
its constant-time claims are written down, file by file, in
SECURITY.md; and its performance is competitive, although there is
more work to be done.

The algorithm set is complete enough to build serious applications
on: encryption and authenticated encryption, hashes and MACs, key
derivation, key agreement, public-key encryption, signatures, the
three post-quantum families, a validated random generator, and the
key formats other software stores keys in.

It is tested to the same extent. The standards' own vectors are built
into the unit tests, and on top of them run the NIST [ACVP][acvp]
suites and the [Project Wycheproof][wycheproof] files, more than
seventy thousand vector cases before the Monte Carlo suites add
several million chained calls of their own. Every implementation of a
primitive is put through the whole vector set for it, at every key
size, and the whole suite runs on x86-64, aarch64 and riscv64 hardware
rather than on the machine that happens to be to hand. The Goals
section below says exactly what that means.

Work from here will focus on speed and algorithms that are still
missing. The API is still being stabilized, and the version number is
still below one, but the major shape of the library is not expected to
change massively. Expect implementation details to become better
hidden and interfaces to be streamlined for usability.

It builds on stable Rust 1.88 or later, on any architecture,
with or without an operating system under it.

## Trying it

```sh
cargo add scytale
```

```rust
use scytale::aead::{Aead, Gcm};
use scytale::cipher::aes::Aes256;
use scytale::random::CtrDrbg;
use scytale::{KeyType, Random};

let mut rng = CtrDrbg::from_system()?;
let key = Aes256::random_key(&mut rng)?;
let mut nonce = [0u8; 12];
rng.fill(&mut nonce)?;

let gcm = Gcm::<Aes256>::new(&key);
let header = b"to: alice";
let mut message = *b"attack at dawn";
let mut tag = [0u8; 16];

gcm.encrypt(&nonce, header, &mut message, &mut tag)?;
gcm.decrypt(&nonce, header, &mut message, &tag)?;
assert_eq!(&message, b"attack at dawn");
```

That is the whole setup: no builder, no context object, no global
state to initialise, and no choice to make about which implementation
to run. `Aes256` asks the processor what it can do the first time a
key is expanded, and every call after that is one predictable branch.
The same binary does that on a laptop with VAES and on a board with
no cryptographic instructions at all.

The API documentation is on [docs.rs](https://docs.rs/scytale), and
`cargo doc --open` builds it locally.

## Goals

**Correct.** Every implementation is checked against the standard
test vectors, against the NIST Automated Cryptographic Validation
Program (ACVP) vectors, and against Project Wycheproof, whose cases
are chosen to break implementations rather than to exercise them.
The corpus is 119 files holding 88,084 cases, and every case this
build can run is run; the Monte Carlo groups chain a thousand cipher
calls per case, with the key re-derived at each step. Every
implementation is put through the whole vector set for its primitive,
at every key size, the modes and the AEADs included: each engine
written for a particular instruction set is validated as itself
rather than only the one this processor would pick. Every
implementation is also compared byte for byte against the portable
one across a range of buffer lengths, so the paths that only some
processors take get the same scrutiny as the rest.

What a given machine actually ran, and what it skipped for want of
instructions, is a command away:

```sh
cargo test --lib acvp::inventory -- --nocapture
```

**Fast.** Where a processor has instructions for a primitive, scytale
uses them, through hand-written assembly rather than compiler
intrinsics, so the instruction order and register use can be tuned.
The block loops interleave enough independent work to keep pipelined
units busy, and a short buffer is handled in a single pass of the
right width rather than one block at a time.

**Portable.** Every primitive has a pure Rust implementation that
works anywhere, with no lookup tables and no data-dependent branches,
so it is constant time. The accelerated versions are additions to
that, never a requirement.

**No setup.** The library is `no_std`, has two dependencies
(`zeroize`, and `getrandom` where there is an operating system to
ask), and builds with nothing but a stable Rust toolchain: no
C compiler, no build script, no feature flags, no target-specific
compiler options. Which implementation to run is decided at run time,
by asking the processor what it supports, so one binary works across
a whole architecture.

## Supported algorithms

Every public module is named for the job a caller wants done, not for
the machinery behind it:

| Module | Job | Algorithms |
| --- | --- | --- |
| `aead` | authenticated encryption | GCM, GCM-SIV, XPN, CCM, ChaCha20-Poly1305 |
| `cipher` | encryption | AES, ChaCha20, and the modes built on them |
| `hash` | digests | SHA-2, SHA-3, SHAKE, cSHAKE; SHA-1 for what still names it |
| `mac` | message authentication | HMAC, CMAC, KMAC, Poly1305 |
| `kdf` | key derivation | HKDF, PBKDF2 |
| `kem` | key encapsulation | ML-KEM-512, -768 and -1024 |
| `kex` | key agreement | X25519, ECDH over P-256, P-384 and P-521 |
| `pke` | public-key encryption | RSA-OAEP |
| `sig` | signatures | Ed25519, ECDSA over P-256, P-384 and P-521, ML-DSA, SLH-DSA, RSA-PSS, RSA PKCS#1 v1.5 |
| `random` | random numbers | CTR_DRBG over AES-256, and what seeds it |
| `constant_time` | comparing secrets | equality whose timing says nothing |
| `codec` | bytes as text | hex, base64 and PEM, in constant time |

### Ciphers

| Algorithm | Key sizes | Notes |
| --- | --- | --- |
| AES (FIPS 197) | 128, 192, 256 | the block cipher itself |
| ChaCha20 (RFC 8439) | 256 | a stream cipher; no tables, no AES needed |

### Authenticated encryption

These encrypt a message and authenticate it together, and refuse to
hand back a message whose tag does not check. Unless a protocol
dictates otherwise, start here.

| Construction | Notes |
| --- | --- |
| GCM | the default; GMAC is GCM with no plaintext |
| GCM-SIV | survives a repeated nonce (RFC 8452) |
| XPN | GCM under a MACsec extended packet number |
| CCM | counter mode with CBC-MAC (SP 800-38C); Bluetooth, 802.15.4, CCMP |
| ChaCha20-Poly1305 (RFC 8439) | GCM's equal; faster without AES hardware |

The first four are modes of operation of a block cipher and are
generic over it; the fifth is a stream cipher and a MAC designed
together, with no block cipher underneath. They share a module because
what a caller wants is authenticated encryption, not a particular way
of building it, and they share a trait for the same reason.

### Modes of operation

Every mode below is generic: it wraps any block cipher, and AES is
simply the one there is so far. The key width is part of the type,
`Aes128`, `Aes192` or `Aes256`, so a key of the wrong length is a
compile error rather than a run-time one. None of them authenticates
anything, so each must be paired with a MAC over the ciphertext,
checked before decrypting; the `aead` module has already done that
work.

| Mode | Kind | Notes |
| --- | --- | --- |
| CBC | confidentiality | whole blocks only; `cipher::padding` fills the last one |
| CFB1, CFB8, CFB128 | confidentiality | the three NIST segment sizes |
| OFB | confidentiality | |
| CTR | confidentiality | |
| XTS | disk sectors | ciphertext stealing for a partial block |
| FF1, FF3-1 | format preserving | see their documentation first |
| KW, KWP | key wrapping | deterministic; for keys, not messages |

`encrypt_blocks` on the cipher itself encrypts each block
independently, which is ECB. On its own that is not a safe way to
encrypt a message, because equal blocks produce equal ciphertext. Use
a mode.

Most initialisation vectors need to be *unique* rather than random,
which is a stronger requirement. `cipher::Nonces` counts nonces so a
repeat is impossible rather than merely unlikely: it splits the nonce
into a fixed part and a counter, wherever the caller puts the
boundary.

Key wrapping is the odd one out: it takes no nonce and is
deterministic, so wrapping the same key twice gives the same answer.
That is safe for a key, which cannot be guessed, and unsafe for
anything an attacker might guess and confirm. Its output is eight
bytes longer than its input, which is where the check value lives.

The two format-preserving modes are not constant time: they do
arithmetic in the caller's radix, and division is not a constant-time
instruction on any of these processors. Their documentation says so
too.

### Hashes

| Hash | Digest | Notes |
| --- | --- | --- |
| SHA-224, SHA-256 (FIPS 180-4) | 28, 32 bytes | the 32-bit family |
| SHA-384, SHA-512 | 48, 64 bytes | the 64-bit family |
| SHA-512/224, SHA-512/256 | 28, 32 bytes | truncated; no length extension |
| SHA3-224 to SHA3-512 (FIPS 202) | 28 to 64 bytes | no length extension |
| SHAKE128, SHAKE256 | any length | extendable output |
| cSHAKE128, cSHAKE256 (SP 800-185) | any length | SHAKE with a function name and customization |
| SHA-1 (FIPS 180-4) | 20 bytes | broken for collisions; for HMAC, HKDF and OAEP in old protocols only |

All of them take bit strings as well as bytes, as the standards
define them.

### Message authentication

| Construction | Notes |
| --- | --- |
| HMAC (FIPS 198-1) | over any hash; constant-time verify |
| CMAC (SP 800-38B) | over any block cipher; constant-time verify |
| KMAC128, KMAC256 (SP 800-185) | over cSHAKE; any output length, KMACXOF, bit strings |
| Poly1305 (RFC 8439) | one-time key; for the AEAD |

### Key derivation

| Construction | Notes |
| --- | --- |
| HKDF (RFC 5869) | over any hash; from a secret that is already random |
| PBKDF2 (SP 800-132) | over any hash; from a password |

### Key encapsulation, key agreement, public-key encryption and signatures

Four jobs, four modules. RSA does two of them, and its signing and
encryption keys are distinct types: a key does one job.

| Algorithm | Module | Notes |
| --- | --- | --- |
| ML-KEM (FIPS 203), all three sets | `kem` | post-quantum; implicit rejection; seed and expanded keys |
| X25519 (RFC 7748) | `kex` | shared secret needs HKDF; refuses low-order keys |
| ECDH (SP 800-56A) over P-256, P-384, P-521 | `kex` | every public key checked on the curve; compressed points read |
| RSA-OAEP (RFC 8017) | `pke` | constant-time unpadding; no v1.5 decryption, ever |
| Ed25519, Ed25519ctx, Ed25519ph (RFC 8032) | `sig` | deterministic; refuses malleable signatures; context strings |
| ECDSA (FIPS 186-5) over P-256, P-384, P-521 | `sig` | RFC 6979 nonces; r \|\| s and DER signature forms |
| RSA-PSS, RSA PKCS#1 v1.5 (RFC 8017) | `sig` | any width; CRT signing and key generation |
| ML-DSA (FIPS 204), all three sets | `sig` | post-quantum; hedged or deterministic; context strings |
| SLH-DSA (FIPS 205), all twelve sets | `sig` | post-quantum, hash-based; hedged or deterministic; context strings |
| RSA primitives (RFC 8017) | `sig`, `pke` | raw, unpadded; for building schemes and for validation |

Every key reads and writes the formats other software stores it in:
a public key as a DER `SubjectPublicKeyInfo`, a private key as
PKCS#8, RSA keys in the bare PKCS#1 forms too, and any of them in
PEM. Encrypted keys are not read.

## Random numbers

Keys and initialisation vectors need randomness, so `scytale::random`
provides a generator you hold:

```rust
use scytale::cipher::aes::Aes256;
use scytale::random::CtrDrbg;
use scytale::{KeyType, Random};

let mut rng = CtrDrbg::from_system()?;

// A key of the right width for the cipher, which wipes itself.
let key = Aes256::random_key(&mut rng)?;

// Or bytes for anything else.
let mut nonce = [0u8; 12];
rng.fill(&mut nonce)?;
```

`CtrDrbg` is named for what it is, the CTR_DRBG of NIST SP 800-90A:
AES-256 driven by a counter, with its key and counter replaced after
every request, checked against the ACVP vectors for that mechanism
alongside everything else. Seed material of any length and any
density is condensed by the standard's derivation function, so
entropy from a slow or biased source is worth its full weight. The
generator takes additional input at a reseeding or a single request,
to bind the output to something the caller knows, and `below` draws
an unbiased number under a bound, so an index or a shuffle never
comes from a byte reduced modulo something.

`from_system` asks this machine for the seed, which is what almost
every caller wants, and it is one call with one shape on every
target, so nothing built on it has to say where it runs. Entropy you
gather any other way goes in by implementing `random::Entropy` over
it and handing that to `CtrDrbg::try_new`. There is deliberately no
way to build a generator from a seed alone: one with no source cannot
reseed itself, and a seed that is a constant or a test value looks
exactly like a good one. What your code should take is the `Random` trait,
so a second generator, or a fixed sequence in a test, drops in
without it noticing.

| Where it runs | What seeds it |
| --- | --- |
| Linux, Apple systems, the BSDs, Solaris, Windows | the operating system, through `getrandom` |
| Wasm | the host's crypto object, through the same |
| No operating system | `rdseed` or `rdrand`, `rndr`, or the `seed` register |
| Anywhere | entropy you supply, or hardware of your own |

The operating system is asked through the `getrandom` crate rather
than by writing out each kernel's interface here, which is the one
dependency beyond `zeroize`. It is not pulled in at all for a target
with no operating system, and on Linux with no C library it still
makes the system call directly. On wasm it reaches the surrounding
JavaScript, which costs every other target nothing: the binding is
asked for only on that target.

With no operating system there is nobody to ask but the processor.
Those instructions can fail without saying so, and parts have shipped
that return all ones while reporting success, so the raw samples are
health tested in the manner of SP 800-90B: a startup test of a
thousand samples when the source is constructed, and a repetition
count and adaptive proportion test on every sample after that. A
processor whose generator is dead or stuck yields no generator at all
rather than one that hands out its output.

Where the processor has no such instruction either, construction
fails and the program does not start, rather than every later call
failing. That is not the end of the road on such a board: a hardware
generator on a bus, a ring oscillator or a chip on I2C is supplied
through the `random::Entropy` trait, and so is entropy gathered some
other way. Either is served exactly as well as a machine with an
instruction for it.

Because the generator has state, it is yours to look after, and the
rule is this: **a copy of the process holds a copy of the generator,
both copies will hand out the same bytes, and the copy must call
`reseed` or build a fresh generator before it uses one.** A `fork`,
a virtual machine restored from a snapshot, a container restored from
a checkpoint, or a live migration that clones all make such a copy.
Do it where the copy is made, in an `atfork` handler or the first
thing a worker does, not lazily on first use, because the first use
is the nonce. The library does not detect any of this, deliberately:
the only hook is bypassed by raw `clone`, absent without a C library
and blind to snapshots, and a check that is silently wrong on some
platforms is worse than a rule that is true on all of them. The
reasoning and what each primitive loses are in SECURITY.md and the
`random` module documentation. The state is wiped when the generator
is dropped.

## Supported architectures

| Architecture | Acceleration used | For |
| --- | --- | --- |
| x86-64 | VAES on 256-bit registers | AES |
| x86-64 | AES-NI on 128-bit registers | AES |
| x86-64 | PCLMULQDQ | GHASH |
| aarch64 | ARMv8 cryptography extension | AES |
| aarch64 | PMULL | GHASH |
| riscv64 | vector cryptography (Zvkned) | AES |
| riscv64 | scalar cryptography (Zkne, Zknd) | AES |
| riscv64 | vector GHASH (Zvkg) | GHASH |
| riscv64 | vector carry-less multiply (Zvbc) | GHASH |
| riscv64 | scalar carry-less multiply (Zbc, Zbkc) | GHASH |
| x86-64 | SHA-NI | SHA-256, SHA-1 |
| aarch64 | ARMv8 SHA1 extension | SHA-1 |
| aarch64 | ARMv8 SHA2 extension | SHA-256 |
| aarch64 | ARMv8 SHA512 extension | SHA-512 |
| riscv64 | vector cryptography (Zvknha, Zvknhb) | SHA-256, SHA-512 |
| riscv64 | scalar cryptography (Zknh) | SHA-256, SHA-512 |
| aarch64 | ARMv8 SHA3 extension | SHA-3, SHAKE, cSHAKE, KMAC |
| x86-64 | BMI1 and BMI2 | SHA-3, SHAKE, cSHAKE, KMAC |
| riscv64 | scalar bit manipulation (Zbb) | SHA-3, SHAKE, cSHAKE, KMAC |
| x86-64 | BMI2 and ADX | RSA, P-256 and P-384 field arithmetic |
| x86-64 | AVX2 | ChaCha20 |
| aarch64 | NEON | ChaCha20 |
| riscv64 | vector extension with Zvkb | ChaCha20 |
| riscv64 | scalar rotates (Zbb, Zbkb) | ChaCha20 |
| any | none needed; portable Rust | all |

The x86-64 and arm64 rows are exercised on real silicon: the
continuous integration matrix runs the whole test suite natively on
runners of both, so the assembly is run by the processor it was
written for. The RISC-V rows are not. The riscv64 runner is a plain
`rv64imafdcsu` machine with none of the extensions below, so it
reports every one of those rows as unavailable, and they are covered
under qemu instead -- at two vector lengths, which is more than one
machine would give, but it is emulation and not silicon.

GHASH is the hash inside GCM, GCM-SIV and XPN. Without a carry-less
multiply instruction it costs more than the cipher does. SHA-224 and
SHA-384 and the SHA-512/t pair use the SHA-256 and SHA-512 code, so
whatever accelerates those accelerates them. x86-64 has no SHA-512
instruction in common use, so SHA-512 is portable there. Every SHA-3,
SHAKE and cSHAKE function, and KMAC, is the one Keccak permutation,
which only AArch64 has instructions for. On x86-64 the portable
permutation is compiled a second time for BMI1 and BMI2, whose
`andn` and `rorx` are chi and rho in fewer instructions, and on
RISC-V for Zbb, whose `andn` and `rori` are the same two; elsewhere
it is portable. ChaCha20 needs no
special instructions, only a vector unit: several blocks are computed
at once, eight with AVX2, four with NEON, and as many as a register
holds on RISC-V. Poly1305 is portable everywhere.

The prime curves and RSA are integer arithmetic rather than a
primitive with instructions of its own, and what they use is the
pair of add-with-carry chains `adcx` and `adox`, with `mulx` to keep
the flags free: the 256-bit field product and square, and RSA's
Montgomery block, are written out for those. Everything above them,
the point formulas and the windows, is Rust.

Support is detected while the program runs: on x86-64 with CPUID, on
aarch64 by reading the ID registers, on RISC-V through the kernel's
`riscv_hwprobe` call. A processor without the instructions falls back
to the portable code.

## Documentation

The API documentation for the main branch is at
<https://6d7770.github.io/scytale/>. Released versions are on
[docs.rs](https://docs.rs/scytale). Locally, `cargo doc --open`. One
copy serves every architecture: the implementations that exist only
on one of them are private, so the documentation does not vary with
the target.

## Using it

```rust
use scytale::cipher::aes::Aes128;
use scytale::cipher::BlockCipher;

let aes = Aes128::new(&key); // key: Key<[u8; 16]>

let mut block = [0u8; 16];
aes.encrypt(core::slice::from_mut(&mut block));
aes.decrypt(core::slice::from_mut(&mut block));

// Any number of blocks, each encrypted independently.
aes.encrypt(&mut blocks); // blocks: [[u8; 16]; N]
```

An AEAD wraps the cipher. It returns a tag, and decryption checks it
before the plaintext is worth anything:

```rust
use scytale::aead::{Aead, Gcm};
use scytale::cipher::aes::Aes128;

let gcm = Gcm::<Aes128>::new(&key);

let mut tag = [0u8; 16];
gcm.encrypt(&nonce, associated_data, &mut buffer, &mut tag)?;
gcm.decrypt(&nonce, associated_data, &mut buffer, &tag)?;
```

GCM, GCM-SIV, CCM and ChaCha20-Poly1305 share an `Aead` trait, so code
that does not care which one it was handed -- a protocol that
negotiated it, a format that records it -- can hold any of them behind
one type. XPN stays out of it: its nonce is two separate halves, a
secret salt and a frame identifier, and only the caller knows which is
which. Most of these also have an incremental form for data that
arrives in pieces. Note that incremental decryption hands back
plaintext before the tag has been checked; the one-shot call above is
the safe default.

Hashes and MACs take their message in pieces or in one call, and a MAC
is checked with `verify`, never by comparing bytes yourself:

```rust
use scytale::hash::{sha2::Sha256, Hash};
use scytale::mac::{hmac::HmacSha256, Mac};

let digest = Sha256::digest(message);

let tag = HmacSha256::mac(&key, message);
let mut mac = HmacSha256::new(&key);
mac.update(message);
mac.verify(&tag)?;
```

### One type per algorithm

`Aes128`, `Aes192` and `Aes256` are the ciphers; `Sha256`,
`Sha3_256`, `Shake128` and the rest are the hashes. Each picks the
best implementation this processor supports, probing once on first
use, and then dispatches with a single predictable branch.

Which implementation that is is not a choice a caller makes. The
implementations are private: hardware instructions where the processor
has them, otherwise constant-time portable code. There is a
table-driven AES in the crate that is about seventy percent faster
than the constant-time portable one, and it is never chosen, because
it indexes tables with bytes derived from the key and so leaks the key
to an attacker who can measure cache timing. A way for an application
that runs nothing untrusted to ask for it by name is still to be
designed.

### Keys wipe themselves

A key is a `Key<[u8; 16]>`, not a `[u8; 16]`. It wipes itself when
it goes out of scope, and it is not `Copy`, so a second copy of a
key is something someone wrote rather than something that happened.
The type carries the width, so the wrong one will not compile.

```rust
use scytale::cipher::aes::Aes128;
use scytale::{Key, KeyType};

let key = Aes128::random_key(&mut rng)?;   // drawn and protected
let key = Key::from([0u8; 16]);            // from bytes you have
let key = Key::take(&mut bytes);           // and wipe where they were
```

`Key::take` is the one worth reaching for when a key arrives in a
buffer of your own: the buffer is the copy that nothing else would
erase.

The expanded key inside a cipher is wiped when the cipher is
dropped, as it always was, and the generator wipes its state.

### In place of ring

[`scytale-ring`](scytale-ring) presents ring 0.17's API over scytale,
under the library name `ring`, so code written against ring compiles
unchanged:

```toml
[dependencies]
ring = { package = "scytale-ring", version = "0.9" }
```

rustls and rustls-webpki pass their own test suites on it
(`scripts/test-ring-downstream`). Its README says where it differs
from ring, the main difference being deterministic ECDSA signatures.

### From a shell

[`scytale-cli`](scytale-cli) builds a `scytale` command for scripts,
one subcommand per module of the library:

```sh
cargo install scytale-cli

scytale random 32 --raw -o key.bin
scytale aead encrypt aes-256-gcm -k file:key.bin -n hex:$NONCE \
    --aad str:v1 < report.pdf > report.sealed
scytale aead decrypt aes-256-gcm -k file:key.bin -n hex:$NONCE \
    --aad str:v1 < report.sealed > report.pdf

scytale key generate ml-dsa-65 -o sign.pem
scytale key public sign.pem -o sign.pub
scytale sig sign ml-dsa-65 -k sign.pem release.tar > release.sig
scytale sig verify ml-dsa-65 -p sign.pub -s file:release.sig release.tar
```

The algorithm is the first word after the verb on every call, never
an option and never defaulted. Keys and every other byte-valued
option are written `hex:`, `file:`, `fd:`, `env:` or `str:`, never
bare, so a value is never read the wrong way, and a key of the wrong
length for the algorithm is refused rather than padded or cut, with
both lengths in the message. Encryption streams, so a pipe of
any size goes through in fixed memory; authenticated decryption
writes nothing until the tag has checked. Exit status 1 means a tag,
signature or padding did not verify, 2 a request that could not be
carried out as asked, 3 anything else. No configuration file, no
privileges, and no cryptography of its own: everything it does, the
library does. `scytale list` prints every algorithm name; `--help`
on any subcommand says what it takes.

## Speed

Measured on a 13th Gen Intel Core i7-1355U, one thread pinned to a
performance core, on mains power. Over 16 KB buffers, in bytes a
second counted in millions and thousands of millions:

| What | Implementation | Speed |
| --- | --- | --- |
| AES-128-GCM encrypt | `vaes` | 14.0 GB/s |
| AES-128-GCM encrypt | `aesni` | 8.6 GB/s |
| AES-128-GCM encrypt | `bitsliced` | 272 MB/s |
| SHA-256 | `shani` | 2.4 GB/s |
| SHA-256 | `portable` | 349 MB/s |
| ChaCha20-Poly1305 encrypt | `avx2` | 2.7 GB/s |

ChaCha20-Poly1305 is the one to reach for where the processor has no
AES instructions: there it is several times faster than any AES here,
which is what it is for.

Every other construction, every implementation of each, and the key
agreement, signature and post-quantum operations are measured too.
Complete runs ship with the crate, in `benchmarks/`, one file per
machine, each recording the date and the commit it measured:
[i7-1355u][bench] is this one. The benchmark ships with the library
too, so these are numbers you can reproduce:

```sh
taskset -c 0 scripts/bench
```

The pin matters on a hybrid processor: unpinned, a row records which
core the scheduler picked rather than how fast the code is. A full
pass has only been saved for this x86-64 machine; the ARM and RISC-V
implementations are measured a few rows at a time on the native CI
runners, by starting the `Bench` workflow by hand. On a laptop
running on battery, expect about half of each figure.

[bench]: https://github.com/6d7770/scytale/blob/main/scytale/benchmarks/i7-1355u.md

## Testing

```sh
cargo test              # unit tests and the one-shot vector suites
cargo test-extended     # adds the Monte Carlo and large data suites
scripts/test-all-arches # every architecture, foreign ones emulated
scripts/bench           # measures rather than checks
```

The suites live inside the crate, under `#[cfg(test)]`, rather than
in `tests/`: an integration test is a separate crate and would see
only the public types, and each implementation behind them is meant
to be validated in its own right. The benchmark is there for the same
reason, and runs as an ignored test that `scripts/bench` starts.

The ACVP and Project Wycheproof vectors live in
`scytale/tests/vectors` and are not shipped in the published crate,
to keep it small. Building and using the library never needs them;
running the tests from a downloaded crate skips those suites and
leaves the standards' own vectors, which are built into the unit
tests, as the check. The public-key algorithms run against both:
ACVP's ML-KEM, ML-DSA, SLH-DSA, RSA, KTS-IFC, ECDSA, EDDSA, XECDH and
KDA suites, and Wycheproof's ML-KEM, ML-DSA, ECDH, ECDSA, X25519,
Ed25519, RSA signature and RSA-OAEP files, whose deliberately twisted
cases are the point. The
deterministic ECDSA suite checks signatures byte for byte, since RFC
6979 fixes the nonce. RSA is the one algorithm whose raw
primitives NIST publishes vectors for, and those run too: they are the
only external check on a value the crate produces under a private
exponent rather than merely verifies.

`scripts/test-all-arches` runs the host architecture directly and the
others with [cross](https://github.com/cross-rs/cross), which needs
Podman or Docker. It is a development convenience; nothing about it
affects users of the library.

## License

BSD 2-Clause. See `LICENSE`.

The test vectors under `scytale/tests/vectors` come from the NIST
[ACVP-Server][acvp-server] project and carry their own notice, in
`LICENSE.txt` beside them.

[acvp]: https://pages.nist.gov/ACVP/
[acvp-server]: https://github.com/usnistgov/ACVP-Server
[wycheproof]: https://github.com/C2SP/wycheproof
