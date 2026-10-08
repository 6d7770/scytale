# scytale-ring

A drop-in replacement for [ring](https://crates.io/crates/ring) that
does the work with [scytale](https://crates.io/crates/scytale).

It presents ring 0.17's public API, module for module and name for
name, and the library is called `ring`, so code written against ring
compiles and runs unchanged. Behind the API is scytale: no line of
ring's implementation is here.

## Why

ring is an excellent library, and most of the Rust TLS ecosystem is written
against it. A developer might still want the same API answered by a
different implementation:

- **No C compiler, no build script.** ring builds C and assembly
  through `cc`, which needs a working C toolchain for every target and
  is the usual reason a cross-compile or a locked-down build fails.
  scytale is Rust, with its hardware acceleration in `asm!` blocks
  chosen at run time, so this crate builds wherever `rustc` does:
  `no_std`, with no allocator, on a bare board or in wasm.
- **Speed.** scytale's hot loops are hand-written assembly, tuned
  per processor: AES-128-GCM runs at 14 GB/s with VAES and SHA-256
  at 2.4 GB/s with SHA-NI on a laptop core, with figures for every
  algorithm and implementation published in its `benchmarks/`.
- **Testing.** scytale is checked against the NIST ACVP vectors and
  Project Wycheproof, more than 85,000 cases, on every implementation
  of every primitive, on x86-64, ARM64 and RISC-V hardware and on
  eleven emulated processors. This crate then runs ring's own test
  suite and the test suites of rustls and rustls-webpki on top.
- **A second implementation.** Two independent implementations of one
  API let you compare them, test against each other, or keep one as
  a fallback. Switching between ring and this crate is one line of
  a manifest, in either direction.

## Dropping it in

In the manifest of the crate that uses ring, change the dependency:

```toml
[dependencies]
ring = { package = "scytale-ring", version = "0.9" }
```

That is the whole change. `use ring::aead;`, `ring::digest::SHA256`,
`signature::EcdsaKeyPair::from_pkcs8`, and everything else keep
working, because the package is presented under the library name
`ring`. Change the line back, and ring is back.

To see it done, this repository does exactly that to ring's own test
suite: `ring-tests/Cargo.toml` holds the line above, and the files
under `ring-tests/tests/` are ring's, byte for byte, passing against
scytale.

### What it does not reach

The line changes what *your* crate's `ring` means. A dependency that
names ring itself, such as rustls or rustls-webpki, keeps the ring in
its own manifest: cargo's `[patch]` cannot substitute a package under
another name, and this package is not called `ring`. To run such a
crate over scytale, make the same one-line change in its manifest;
`scripts/test-ring-downstream` in the scytale repository does that to
rustls and rustls-webpki and runs their test suites, which pass.

From rustls 0.24, which takes its cryptography from a provider the
program names, use [rustls-scytale](https://crates.io/crates/rustls-scytale)
instead: it is that provider, built on scytale directly.

## Which ring

The version number is scytale's, since the two are released together,
so it says nothing about ring. This table does:

| scytale-ring | ring API | Tested with |
| --- | --- | --- |
| 0.8, 0.9 | 0.17, checked against 0.17.14 | rustls 0.23.45, rustls-webpki 0.103.15 |

A new ring API arrives in a new scytale-ring minor version, and a row
here says so.

## What is tested

- ring's own test suite, every file of it, vendored unchanged under
  `ring-tests/` with its vector files and ring's licence beside them.
  Every test passes; nothing is skipped or altered.
- Unit tests for every module, against published vectors (FIPS 180,
  RFC 4231, RFC 5869, RFC 7748, RFC 8032, RFC 8439, RFC 9001) and
  against keys and signatures made by OpenSSL.
- rustls-webpki 0.103 and rustls 0.23 run their own test suites with
  this crate as their ring, by `scripts/test-ring-downstream` in the
  scytale repository, in CI on every push.

## Where it differs from ring

- **ECDSA signatures are deterministic** (RFC 6979). ring draws a
  random nonce. Signatures from either verify under the other, but
  a test that compares signature bytes with stored ones will not
  match. The random source ring's signing calls take is accepted and
  not used.
- **Keys ring's old versions wrote are read.** ring 0.16 wrote Ed25519
  PKCS#8 with the public key under the wrong tag, and ring still reads
  them; so does this crate, by repairing that one element before
  scytale reads the key. scytale itself refuses them.
- **Minimum Rust is 1.88**, scytale's, where ring's is 1.66.

## Licence

BSD-2-Clause, as scytale. The files under `ring-tests/` are ring's,
under ring's licence, which is beside them.
