# Security

What scytale defends against, implementation by implementation, and
what it does not. Where this file and a module's documentation
disagree, the code is wrong and this file should be treated as the
claim to hold it to.

Vulnerabilities: open an issue on the repository named in
`Cargo.toml`, or contact the maintainer privately through GitHub if
the report is sensitive. There is no bug bounty. This covers
rustls-scytale too (see *rustls-scytale* below); a fault in rustls
or webpki themselves belongs to the rustls project.

## Attacker models

The library is written against these, in order of how much it
promises:

1. **A remote attacker who sees inputs and outputs.** Chosen
   ciphertexts, chosen messages, malformed keys, forged tags and
   signatures. This is what the algorithms themselves are for, and
   the library adds the checks each standard calls for: curve
   points are checked on import and X25519 refuses low-order points,
   ML-KEM public keys are checked for canonical encoding, every AEAD
   refuses to release plaintext under a failed tag, OAEP unpadding
   gives one verdict, ML-KEM rejects implicitly, and DER is read
   strictly so that a key cannot parse two ways.
2. **A remote or local attacker who can time operations.** Wall
   clock at the network, or a co-resident process measuring shared
   caches and branch predictors. The constant-time implementations
   listed below are written so that neither the sequence of
   instructions executed nor the sequence of memory addresses
   touched depends on a secret. The compiler is not verified to
   preserve that (see *Assumptions*).
3. **Not defended: an attacker with physical access or a fault
   injector.** Power, electromagnetic emission, glitching, Rowhammer,
   cold boot. See *What scytale does not protect against*.

A secret, for the purposes of this file, is a private or symmetric
key, a nonce that must stay unknown (ECDSA), a plaintext, a shared
secret, a decapsulated key, an RSA prime, a DRBG state, or any value
derived from those. Lengths are not secrets: the width of a key, the
length of a message and the number of blocks are visible in every
operation.

## Constant-time implementations

"Constant time" here means: for a fixed set of lengths, the
instruction sequence and the memory access sequence are independent
of secret values. Each entry says how that is achieved and what is
excluded.

### Symmetric

| Primitive | Implementation | How |
| --- | --- | --- |
| AES, portable | `cipher/aes/portable/bitsliced.rs` | bitsliced: the S-box is a Boolean circuit, no tables |
| AES, x86-64 | AES-NI and VAES assembly | the instructions are data-independent |
| AES, AArch64 | ARMv8 crypto extension assembly | same |
| AES, RISC-V | Zkn scalar and Zvkned vector assembly | same |
| AES, table-driven | `cipher/aes/portable/ttable.rs` | **not constant time**; compiled and tested, never selected by any construction; there is currently no way to ask for it |
| ChaCha20, all | add-rotate-xor only | no tables, no data-dependent branches, on every backend |
| GHASH, portable | 128 masked shift-and-add steps per block | no tables; slow on purpose |
| GHASH, accelerated | `pclmulqdq`, `pmull`, Zvbc/Zbc/Zvkg | carry-less multiply instructions are data-independent |
| POLYVAL (GCM-SIV) | over the GHASH multiply | same |
| Poly1305, portable and x86-64 | limb arithmetic, final reduction chosen by mask | no branch or index on key or message |
| SHA-1, SHA-2, SHA-3, SHAKE, cSHAKE | all backends | no data-dependent control flow; hashing a secret leaks only its length |
| HMAC, HKDF, PBKDF2, TLS 1.2 PRF | over the hashes | as the hash; `Mac::verify` compares with `constant_time::equal` |
| KMAC | over cSHAKE | as the hash; `verify_tag`, `verify_bits` and `Mac::verify` compare with `constant_time::equal` |
| CTR, CBC, CFB, OFB, XTS | over the cipher | as the cipher; the modes themselves have no padding |
| PKCS#7 padding | `cipher/padding/pkcs7.rs` | `unpad` reads the whole last block and combines the checks by mask; one error for every failure, documented as the padding oracle it would be if shown to an attacker |
| hex, base64, PEM | `codec/` | each character computed from its value with masks, no table indexed by a secret; a bad character is recorded and reported after the whole string is read |
| CMAC | over the cipher | as the cipher; subkey doubling masks rather than branches; `Mac::verify` compares with `constant_time::equal` |
| KW, KWP | over the cipher | the integrity check value is compared with `constant_time::equal` |
| GCM, GCM-SIV, XPN, CCM, ChaCha20-Poly1305 | over the above | tag compared whole with `constant_time::equal`; plaintext never released on failure |
| CTR_DRBG | AES-256 | as AES; the state is a `Key` |
| `constant_time::equal` | `constant_time.rs` | reads every byte of both operands; the accumulator goes through `black_box` so the compiler cannot reintroduce an early exit; a length mismatch returns early, since lengths are not secret |

### Public key

| Scheme | Secret-handling path | How |
| --- | --- | --- |
| X25519 | `kex/x25519.rs`, `math/fe25519.rs` | Montgomery ladder, swap by mask; 51-bit limb field arithmetic with no tables; a public key is the Ed25519 base comb, table scanned whole, mapped to the Montgomery form by one inversion |
| Ed25519 signing | `sig/ed25519.rs` | fixed ladder of doublings and additions, result by mask; same field |
| Ed25519 verification | `sig/ed25519.rs::mul_add_base_vartime` | variable time, on public data only: one pass over both scalars in signed digits, with an addition for each nonzero digit, so which additions happen and from which entries is what the scalars are. See the table below |
| ECDH P-256, P-384, P-521 | `math/ec/`, `math/montgomery/` | the fixed-base multiplication reads per-window tables of affine multiples for P-256 (37 windows of 64 entries, signed seven-bit Booth digits, no doublings) and the complete projective formulas (Renes-Costello-Batina) over the combs for P-384 and P-521, so neither has a special case for doubling or the identity; the variable-base one, which is where a secret scalar meets an untrusted point, runs in Jacobian coordinates over signed five-bit windows (Booth), where the addition is not complete and every case it misses is settled by a mask and not a branch: either point being the identity takes the other, opposite points the formula handles itself, and two equal points cannot arise above the lowest window, which the module documents; at the lowest they can, for a scalar just below the order, and that window's addition takes the double alongside, chosen by the same mask. Every table read scans the whole table, and the digit only chooses and negates; on x86-64 the 64-entry fixed-base scan is an AVX2 loop in `math/ec/x86_64.rs` that reads every entry whatever the digit, and elsewhere the compiler makes the same scan into 128-bit masked selects. Inversion and square roots are exponentiations whose exponent is a public constant, so their windows are slid over it while the value stays out of the timing; on x86-64 with ADX the field product and square are the assembly in `math/montgomery/x86_64.rs`, and on AArch64 the assembly in `math/montgomery/aarch64.rs`, at P-256's and P-384's widths, while P-521 takes the portable product, which is the same masked limb arithmetic without the carry-chain instructions; and for P-256 the point doubling, both additions and the inversion chain are single assembly blocks, in `math/ec/x86_64.rs` and `math/ec/aarch64.rs`, each a fixed instruction sequence whose subtractions are chosen by mask
| ECDSA signing | `sig/ecdsa.rs` over the same | RFC 6979 nonce, so no randomness is consumed and no bias is possible; the one data-dependent branch is the retry on a zero `r` or `s`, probability 2^-256 |
| ECDSA verification | `math/ec/mod.rs::mul_add_vartime` | variable time, on public data only: one pass over the public key's scalar in signed five-bit digits, with an addition only where a digit is nonzero, and the base point's multiple read from the static per-window table by an index the digit gives, both of which are what the scalars are. See the table below
| RSA private exponentiation | `math/limbs/mod.rs::modexp` | fixed 4-bit windows over the exponent's full limb length; the 16-entry table is scanned whole on every read; the final Montgomery subtraction is chosen by mask; on x86-64 with ADX the multiply is the four-row assembly block in `math/limbs/x86_64.rs`, whose instruction and memory sequence depends only on the length |
| RSA CRT | `math/rsa.rs` | two `modexp` calls and Garner's recombination, all masked; every CRT signature is verified with the public exponent before release, so a fault in one half cannot leak a prime (Boneh-DeMillo-Lipton) |
| HPKE | `pke/hpke.rs` over the same | the key exchanges, HKDF and AEADs above, with no secret-dependent branch of its own; an encapsulation that is off the curve or gives X25519's all-zero secret is refused, and a message that does not authenticate is wiped and does not advance the counter |
| RSA-OAEP decryption | `pke/rsa.rs` | unpadding reads every byte and gives one verdict, so nothing distinguishes a bad first byte from a bad hash (Manger) |
| RSA import | `math/rsa.rs::fill_crt` | the primes are compared and multiplied with masked limb arithmetic; the branches taken are on the outcome (accept or reject), on the bit lengths, which the encoding reveals anyway, and on nothing else |
| ML-KEM | `kem/ml_kem.rs` | coefficient arithmetic branch-free below the modulus, signed 16-bit Montgomery and Barrett multiply-and-shift reductions, no division; decapsulation compares the ciphertext against the re-encryption with `constant_time::equal` and selects the shared secret by mask (implicit rejection) |
| ML-DSA signing | `sig/ml_dsa.rs` | rounding, hints and decomposition written as masks; within a rejection round no branch or index depends on a secret |
| SLH-DSA | `sig/slh_dsa.rs` | a fixed schedule of hash calls; the only values steering control flow are the message digest's indices, which are recomputable from the signature and so public |
| Montgomery setup | `Modulus::prepare`, `Montgomery::known` | the low-limb inverse by Newton iteration, `R^2` by fixed doubling with masked subtraction; no division on a secret modulus; the curve moduli are public and their contexts are made when the crate is built |

## Deliberately variable-time implementations

Each of these varies its time with something. The list says with
what, and why that is accepted.

| Operation | Varies with | Why it is accepted |
| --- | --- | --- |
| RSA public exponentiation (`verify_*`, `encrypt_*`, `modexp_public`) | the public exponent `e` and the modulus length | both are public; square-and-multiply on `e` is six times faster than the windowed loop and leaks nothing that is secret |
| RSA key generation | how many candidates fail trial division and Miller-Rabin | inherent in searching for primes; every implementation does this; the candidates that fail are discarded and their count reveals nothing about the primes kept beyond what the key length already says |
| Miller-Rabin | the candidate, through `Modulus::prepare` and the witness exponentiations | the exponentiations themselves are the constant-time `modexp`; the loop count is fixed at eight rounds; the early exit on a composite reveals that a candidate was composite, which is a value that is then thrown away |
| ECDSA verification (`mul_add_vartime`) | the signature, the public key and the message digest | all three are public: the caller was given the signature to check. The same caveat as Ed25519 below |
| Ed25519 verification (`mul_add_base_vartime`) | the signature, the public key and the message digest | all three are public: the caller was given the signature to check. Where a verifier holds a message an attacker does not, the timing says something about its digest, so do not verify a secret message where an attacker can time it |
| ML-KEM matrix sampling (`SampleNTT`) | the public seed `rho` | the seed is part of the public key |
| ML-DSA signing | the number of rejection rounds | inherent in the scheme (FIPS 204); the count is independent of the key and within a round nothing depends on a secret |
| SLH-DSA | nothing secret | see above; listed here because its running time does vary, with the public message digest |
| FF1, FF3-1 | the plaintext and tweak, through radix division | the modes are defined over arithmetic in the caller's radix and division is not constant time on any target; documented on both modes; do not use them where an attacker can time them |
| `Alphabet` | the text, through a search of the alphabet | the format-preserving modes it serves are not constant time either; a format is not a secret |
| `KeyInfo`, DER and PEM import and export | the structure and lengths of the encoding | DER lengths encode integer bit lengths, so a private key's encoding reveals the bit length of `d`, `p` and `q` whatever the parser does; the reader branches on structure but not on the value of any integer; treat a key's encoded form as a secret with the same care as the key |
| `constant_time::equal` on unequal lengths | the lengths | lengths are not secret |
| Implementation selection | the processor | asked once per process, in `probe.rs`, and every call thereafter is one predictable branch; not secret-dependent |
| Every operation | its lengths | see *Attacker models* |

Nothing in the crate makes an early exit on a secret comparison.
Nothing indexes a table by a secret byte except the table-driven AES,
which nothing selects.

## Cache, branch, power and EM assumptions

**Cache and branch.** The constant-time claims above are claims
about the source and the assembly. For the portable Rust code they
rest on the compiler preserving the property, which LLVM does not
promise: a masked select can be lowered to a branch, and a loop that
reads a whole table can be turned into a lookup. The crate uses the
idioms that are known to survive current compilers (masks built by
wrapping negation, selection by AND and XOR, `black_box` on the
equality accumulator) and the hand-written
assembly is immune to this by construction. There is no
dudect-style or Valgrind-taint timing test in the test suite. If
you need a guarantee against a particular compiler, audit the
generated code.

**Memory access granularity.** Where a table is scanned whole, the
scan touches every cache line of it, so an attacker seeing cache
lines learns nothing. It does not defend against an attacker who can
see which *word* within a line is used, which no shared-cache attack
can and a hardware debugger can.

**Speculative execution.** Nothing here mitigates Spectre-class
attacks. A secret in memory is subject to whatever the platform
allows a co-resident attacker to read speculatively, and that is the
platform's problem to solve, not a library's.

**Power and electromagnetic emission.** Not defended. A bitsliced
AES has a data-dependent Hamming weight; scalar multiplication leaks
through power however it is scheduled. Masking against differential
power analysis is not implemented anywhere. Do not run these
implementations on a smart card or in a device an attacker holds
without adding those countermeasures yourself.

**Fault injection.** Not defended, with one exception: every RSA CRT
signature is checked against the public key before release, because
a single faulted half-exponentiation would otherwise reveal a prime.
Nothing else is double-checked. ML-DSA and SLH-DSA are hedged by
default, which is a partial fault defence the standards call for:
a fault in a hedged signature does not reveal the key the way it does
in a deterministic one. Ed25519 is deterministic, as RFC 8032
defines it, and so is exposed to fault attacks on the nonce.

## Memory safety

- The crate is `#![no_std]` and `#![deny(unsafe_code)]`. The only
  modules that allow it are the ones holding `asm!` blocks for a
  processor instruction, and the probes that read CPUID or its
  equivalent; each `unsafe` block has a `# Safety` note stating what
  it relies on. Nothing else in the crate is `unsafe`, so the
  portable code has Rust's ordinary guarantees: no buffer overruns,
  no use after free, no uninitialised reads.
- Every assembly block is reached through a value that only the
  probe can create, so the instructions it uses have been confirmed
  present before it can be called. A wrong length is caught by a
  slice check in Rust before the pointer is handed to assembly.
- Production paths do not `unwrap`, `expect` or `panic!`. Every
  fallible call returns `Result<_, Error>`. An out-of-range index
  would still panic, as in any Rust; none is known.
- Secrets are wiped. `Key<B>` is `ZeroizeOnDrop` and not `Copy`.
  Every private key type, every expanded key schedule, the DRBG
  state, hash and MAC states, and the scratch buffers RSA and the
  post-quantum schemes work in are zeroized when dropped or when
  the operation finishes. `Debug` on a key prints no key material.
- Wiping has limits. Rust moves values by copying, and the compiler
  may spill any value to the stack or leave a copy in a register or
  a caller's frame; `zeroize` clears the location the type owns, not
  every copy that ever existed. A signing operation's temporaries
  are on the stack and are zeroized by their owners, but the stack
  frames below them are not scrubbed. If your threat model includes
  reading process memory after the fact, that is a partial defence.
- Nothing is allocated. There is no allocator dependency, so no
  secret ever goes to a heap the library does not control, and no
  operation's memory use depends on a secret (see below).

## Entropy failure

- `CtrDrbg::from_system` asks the operating system through
  `getrandom`. On Linux that blocks until the kernel's pool is
  initialised rather than returning early bytes. A system error is
  returned as `Error::EntropyUnavailable(code)`; nothing weaker is
  substituted, and no fallback to a clock or a process id exists.
- Where there is no operating system (`target_os = "none"`), the
  processor's own generator is used: `rdseed` (or `rdrand` if only
  that exists) on x86-64, `rndr` on AArch64, the `seed` CSR on
  RISC-V. Every sample passes the SP 800-90B repetition-count and
  adaptive-proportion health tests, with each 16-bit sample credited
  with 8 bits of entropy, on start-up and continuously. A source
  that sticks or collapses is reported as an error, not used. A
  processor with no generator fails construction with
  `Error::NotSupported`, and a program that needs randomness does
  not start.
- Seed material is drawn at twice the required length and
  conditioned through the CTR_DRBG derivation function; the
  generator needs `MIN_SEED` (48 bytes: 256 bits of strength plus a
  128-bit nonce) and refuses less. The construction without the
  derivation function is implemented so that its vectors run, but is
  crate-private: it trusts every byte of its seed as full entropy,
  and that is not a contract to offer callers. Additional input, at
  a reseeding or a request, is never credited as entropy.
- There is no public way to build a generator from a seed alone.
  Entropy the caller gathers goes in through an `Entropy`
  implementation, so every generator a caller can hold has a source
  to return to. After `RESEED_INTERVAL` (2^48) requests it reseeds
  from that source; if the source refuses, `fill` fails with the
  source's error until a reseeding succeeds. It never silently
  continues.
- One request is capped at `MAX_REQUEST` (65536) bytes;
  `Error::RequestTooLarge` otherwise.
- The generator is checked against the ACVP CTR_DRBG vectors. The
  entropy sources are not, since there is nothing deterministic to
  check; the health tests are checked against streams with known
  faults.

## RNG across fork, virtual machines and snapshots

A `CtrDrbg` is a value you hold, and its state is the whole secret.
Anything that duplicates the process duplicates the next bytes. The
rule, stated here, in the README and on every constructor: **the copy
must call `reseed` or build a fresh generator before it uses one, and
the library does not do it for you.**

- **What makes a copy**: `fork` and everything built on it, `clone`
  without shared memory, `vfork`; a virtual machine restored from a
  snapshot; a container restored from a checkpoint (CRIU); live
  migration that leaves the original running; a disk image cloned
  with a warm process on it. Every one duplicates the state exactly,
  and the next request on each side returns the same bytes.
- **What to do**: in the copy, before the generator is used for
  anything, call `reseed`, which draws fresh material from the
  generator's source, or drop it and build another. Do it where the
  copy is made: the child side of a `pthread_atfork` handler, the
  first thing a spawned worker does, the resume hook of whatever
  restores the snapshot. Not lazily on first use, because the first
  use is the nonce. Better still, do not share a generator across the
  copy: build one per worker after the worker exists.
- **After a snapshot restore** the operating system's generator is
  the source that knows a clone happened: it is told through
  `vmgenid` and virtio-rng where the hypervisor supports them, and
  nothing in user space is. A generator on `entropy::System`
  reseeded after restore is sound; one built before the snapshot and
  not reseeded is not.
- **Why the library does not detect it**: the only hook is
  `pthread_atfork`, which a raw `clone` or `vfork` never runs, which
  does not exist on a build with no C library, and which knows
  nothing about snapshots, since no operating system reports a clone
  to user space. A check that is silently wrong on some platforms is
  worse than a rule that is true on all of them. Detection was
  considered and rejected on those grounds; it is not a gap awaiting
  a patch.
- The generator is deliberately not `Clone`, so a second copy in the
  same process is not something that can happen by accident, and
  there is no public constructor from a seed alone, so every
  generator a caller holds has a source to reseed from.
- The state is zeroized on drop.
- A repeated output is a repeated nonce, and a repeated GCM or
  ChaCha20-Poly1305 nonce loses the key. Ed25519, RFC 6979 ECDSA and
  deterministic ML-DSA and SLH-DSA draw no randomness when signing
  and are unaffected; hedged ML-DSA and SLH-DSA, RSA-PSS salts and
  OAEP seeds degrade to their deterministic security, which is still
  sound; RSA and ML-KEM key generation and ML-KEM encapsulation under
  a duplicated generator produce duplicated keys and shared secrets.

## Secret-dependent allocation

There is none, because there is no allocation. The crate has no
`alloc` dependency, and every buffer is a fixed-size array on the
stack or in the caller's storage:

- RSA works in a caller-supplied or stack `[u64; scratch_words(bits)]`
  sized by the key's bit length, which is public.
- ML-KEM, ML-DSA and SLH-DSA use fixed arrays sized by the parameter
  set.
- Signing, decryption and decapsulation touch the same amount of
  memory whatever the secret.

The stack depth of an operation therefore depends on the algorithm
and the key length and on nothing secret. An attacker observing
memory use, page faults or stack high-water marks learns those
lengths only.

## rustls-scytale

The provider implements no cryptography: every algorithm it offers
is one of scytale's above, and what this file says of that holds
here. What the provider adds is framing, checks and key handling,
and this is what it promises about them.

- **Memory safety.** The crate is `#![forbid(unsafe_code)]`, and its
  production paths do not `unwrap`, `expect` or `panic!`.
- **Records.** A TLS record or QUIC packet that does not
  authenticate is an error and its plaintext is wiped, as scytale's
  AEADs do. Nonces are built from the record or packet number rustls
  hands over, never drawn at random. A TLS 1.2 record of more than
  16,384 bytes of plaintext is refused here, since rustls checks
  that limit for TLS 1.3 only.
- **Key shares.** Every share a peer sends is checked before use,
  and any failure is rustls's `InvalidKeyShare`. An X25519 exchange
  giving the all-zero secret is refused; a P-256 or P-384 share must
  be an uncompressed point of exactly the right length and on the
  curve; an ML-KEM encapsulation key must be canonically encoded and
  a ciphertext exactly the right length. Shared secrets are wiped
  once rustls has its copy.
- **Session tickets.** Sealed with ChaCha20-Poly1305 under a key
  rotated every six hours, with a random nonce and the key's name as
  the associated data. Opening one cannot panic on any input: a
  ticket longer than any issued is refused before it is read, the
  key name is compared with `constant_time::equal`, and a ticket
  that does not open is treated as no ticket.
- **Randomness.** Each request builds a fresh `CtrDrbg` from the
  operating system, so no generator state is held between calls and
  nothing a `fork` or a snapshot copies can repeat; the rule in *RNG
  across fork* does not apply to the provider.
- **Signing.** ECDSA is deterministic (RFC 6979); RSA-PSS salts and
  ML-DSA's hedging come from the randomness above. RSA keys must be
  2048 to 8192 bits.
- **Allocation.** Unlike scytale, the provider allocates: rustls
  holds keys behind `Box` and `Arc`, so traffic keys, signing keys
  and the master secret are on the heap. Each is wiped on drop, with
  the limits *Memory safety* gives for wiping.
- **Not FIPS validated.** Every `fips()` says so.
- **ML-DSA in TLS 1.2.** rustls gives a provider no way to offer a
  signature scheme for TLS 1.3 only, so a TLS 1.2 server's request
  for a client certificate lists ML-DSA, which its specification
  does not define for TLS 1.2. The signatures are as sound there as
  anywhere; the use is outside the standard.
- **Not the provider's.** The handshake state machine, certificate
  path validation and every protocol decision are rustls's and
  webpki's, and are held to their own tests; this provider runs
  rustls's API suite and BoGo, but does not change what they check.

## What scytale does not protect against

- **Nonce reuse.** GCM, XPN, CCM, ChaCha20-Poly1305 and CTR lose
  confidentiality when a nonce repeats under one key, and all but
  CCM give up the authentication key with it. The library counts nonces for you
  when asked (`cipher::Nonces`) but cannot stop a caller supplying
  its own. GCM-SIV survives a repeated nonce at the cost of
  revealing that two messages were equal.
- **Weak or reused keys.** A Poly1305 key used for two messages
  gives away `r`. An RSA key below 2048 bits, or SHA-1 anywhere but
  a legacy HMAC, is accepted where a standard still names it, and is
  not safe against a well-funded attacker.
- **Choosing the wrong primitive.** Raw RSA, ECB-like use of the
  block cipher, unauthenticated CTR and the format-preserving modes
  exist for the protocols that need them. Nothing in the type
  system stops their use elsewhere.
- **Compiler-introduced timing leaks** in the portable code, as
  above.
- **Physical attacks**: power, EM, fault injection, cold boot,
  probing, as above.
- **Speculative-execution side channels** and any other channel the
  platform exposes to a co-resident attacker below the cache-line
  level.
- **Memory disclosure after the fact.** Wiping is best effort; stack
  copies and registers are not scrubbed.
- **A compromised host.** Debuggers, `ptrace`, kernel access, DMA,
  or a hypervisor reading guest memory see every secret.
- **A broken operating system generator.** `from_system` trusts what
  the kernel hands over; the health tests run only on the
  processor's raw source, which the kernel path does not use.
- **Denial of service.** A caller can be made to spend time: RSA key
  generation at 8192 bits, SLH-DSA signing and PBKDF2 with a large
  count are all slow by design, and nothing rate-limits them.
- **Protocol design.** Signatures do not bind context unless the
  scheme has a context string (ML-DSA, SLH-DSA) and the caller uses
  it; key agreement outputs must go through HKDF; ordering, replay
  and identity binding are the protocol's job.
- **Bugs.** The library is checked against NIST ACVP and Wycheproof
  vectors for every algorithm, and every accelerated implementation
  is tested against the portable one at every length. That catches
  wrong answers; it does not prove constant time and it does not
  prove the absence of every bug. It has not had a third-party
  audit.
