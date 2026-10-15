# scytale

[![CI][ci-badge]][ci]
[![crates.io][version-badge]][crate]
[![docs.rs][docs-badge]][docs]
[![MSRV][msrv-badge]][crate]
[![BSD-2-Clause][license-badge]][license]

[ci-badge]: https://github.com/user-serviceable-parts/scytale/actions/workflows/ci.yml/badge.svg?branch=main
[ci]: https://github.com/user-serviceable-parts/scytale/actions/workflows/ci.yml
[version-badge]: https://img.shields.io/crates/v/scytale.svg
[crate]: https://crates.io/crates/scytale
[docs-badge]: https://docs.rs/scytale/badge.svg
[docs]: https://docs.rs/scytale
[msrv-badge]: https://img.shields.io/crates/msrv/scytale.svg
[license-badge]: https://img.shields.io/crates/l/scytale.svg
[license]: LICENSE

Correct, fast, portable cryptography in Rust: the scytale library,
and three crates that put it to work.

## The crates

| Crate | What it is |
| --- | --- |
| [scytale](scytale) | The library. |
| [scytale-ring](scytale-ring) | ring 0.17's API over scytale, under the name `ring`, so code written against ring builds unchanged. |
| [rustls-scytale](rustls-scytale) | A cryptography provider for rustls 0.24: post-quantum key exchange first, ML-DSA, and HPKE for Encrypted Client Hello. |
| [scytale-cli](scytale-cli) | The `scytale` command, the library from a shell. |

Each crate's README is its page on crates.io and says how to use it.
Each has its own version, and a release is tagged with the crate's
name and version, as in `scytale-v0.10.0`; [RELEASING.md](RELEASING.md)
has the procedure.

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

## Building and testing

Everything builds with a stable Rust toolchain, 1.88 or later.

```sh
cargo test                     # every crate's tests
cargo test-extended            # adds the long suites marked #[ignore]
scripts/ci-check               # formatting and style, as CI's style job
scripts/test-all-arches        # every architecture, foreign ones emulated
scripts/test-ring-downstream   # rustls and rustls-webpki on scytale-ring
scripts/test-rustls-downstream # rustls's tests and BoGo on rustls-scytale
scripts/test-openssl-interop   # every rustls-scytale suite against OpenSSL
scripts/bench                  # measures rather than checks
```

Each crate's README says what it is tested against. The ACVP,
Wycheproof and HPKE vectors are in `scytale/tests/vectors` and ring's
suite in `scytale-ring/ring-tests`; neither is in a published crate.

`scripts/test-all-arches` runs the host architecture directly and the
others with [cross](https://github.com/cross-rs/cross), which needs
Podman or Docker. The downstream scripts clone rustls and
rustls-webpki at pinned releases and run their own test suites
against these crates; the rustls one needs Go, a C compiler and `cpp`
for BoGo. `scripts/test-openssl-interop` needs OpenSSL 3.

Continuous integration covers the same ground on every push: every
crate's tests natively on x86-64, arm64 and riscv64 runners and on
32-bit x86 and WebAssembly, the library's under qemu as older and
newer processors of each architecture, the library built for targets
with no operating system, the style checks, the downstream suites,
the interop, and the packaging of every crate. The benchmark runs on
the native runners when the `Bench` workflow is started by hand.

## Security

[SECURITY.md](SECURITY.md) says what each primitive does and does not
protect against, which code is constant time and why, what the
rustls provider adds, and how to report a vulnerability.

## License

BSD 2-Clause. See [LICENSE](LICENSE).

The test vectors under `scytale/tests/vectors` are others' work,
unmodified, each set with its notice beside it: the NIST
[ACVP-Server][acvp-server] project's, Project
[Wycheproof][wycheproof]'s under the Apache License 2.0, and the
CFRG's for [HPKE][hpke]. ring's test suite, vendored in
`scytale-ring/ring-tests`, is under ring's licence, which is beside
it.

[acvp-server]: https://github.com/usnistgov/ACVP-Server
[wycheproof]: https://github.com/C2SP/wycheproof
[hpke]: https://github.com/cfrg/draft-irtf-cfrg-hpke
