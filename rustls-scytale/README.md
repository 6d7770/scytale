# rustls-scytale

A cryptography provider for [rustls](https://github.com/rustls/rustls)
that uses the [scytale](https://github.com/6d7770/scytale) library.

This provider is built against rustls 0.24.0-dev.1, the current
development release, and will move to 0.24.0 when that is released.

This crate is not part of the rustls project, nor endorsed by it in any way.

## Why

- **Builds with the Rust compiler alone.** scytale is Rust, with
  its hardware acceleration in `asm!` blocks chosen at run time, so
  this crate builds wherever `rustc` does.
- **Post-quantum by default.** The first key share offered is
  X25519MLKEM768, and ML-DSA certificates are accepted and served.
- **Testing.** scytale is tested against the NIST ACVP vectors,
  Project Wycheproof and the CFRG's HPKE vectors. This crate then
  passes rustls's own API test suite and BoGo, BoringSSL's TLS
  conformance runner.

## Using it

```toml
[dependencies]
rustls = "=0.24.0-dev.1"
rustls-scytale = "0.9"
```

Hand the provider to a configuration:

```rust,ignore
use std::sync::Arc;

let config = rustls::ClientConfig::builder(Arc::new(
    rustls_scytale::DEFAULT_PROVIDER,
))
.with_root_certificates(roots)
.with_no_client_auth()?;
```

or install it once as the process default, for libraries that build
their own configurations from `CryptoProvider::get_default()`:

```rust,ignore
rustls_scytale::DEFAULT_PROVIDER.install_default().ok();
```

`DEFAULT_TLS13_PROVIDER` and `DEFAULT_TLS12_PROVIDER` are the same
with one protocol version. `examples/client.rs` fetches a page from
a server on the internet, and `examples/server.rs` answers on
localhost.

## What it offers

### TLS 1.3

- **Cipher suites:** AES-128-GCM-SHA256, AES-256-GCM-SHA384 and
  ChaCha20-Poly1305-SHA256 by default; AES-128-CCM-SHA256 and
  AES-128-CCM-8-SHA256 on request (see *AES-CCM*).
- **QUIC:** every suite but AES-128-CCM-8 also protects QUIC
  packets and their headers (RFC 9001), so rustls's QUIC support
  runs on this provider. RFC 9001 forbids the 8-byte tag in QUIC.
- **Key exchange:** X25519MLKEM768 first, then X25519, P-256 and
  P-384. SECP256R1MLKEM768, SECP384R1MLKEM1024 (the hybrid at
  the strength CNSA 2.0 asks for), ML-KEM-768 and ML-KEM-1024 are
  in `ALL_KX_GROUPS` for a program that asks for them.
- **Handshake signatures:** ML-DSA-44, -65 and -87; ECDSA on
  P-256, P-384 and P-521, each with its own hash; Ed25519; RSA-PSS.
- **Encrypted Client Hello:** HPKE with DHKEM over X25519, P-256,
  P-384 and P-521, each with its own hash, and AES-128-GCM,
  AES-256-GCM and ChaCha20-Poly1305, in `hpke`.

### TLS 1.2

- **Cipher suites:** ECDHE-ECDSA and ECDHE-RSA, each with
  AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, by default;
  ECDHE-ECDSA with AES-128-CCM, AES-256-CCM, AES-128-CCM-8 and
  AES-256-CCM-8 on request (see *AES-CCM*).
- **Key exchange:** X25519, P-256 and P-384. The post-quantum groups
  are defined for TLS 1.3 only.
- **Handshake signatures:** ECDSA on P-256, P-384 and P-521, where
  a peer's may pair any of the curves with SHA-256, SHA-384 or
  SHA-512; Ed25519; RSA-PSS and RSA PKCS#1 v1.5.

### Both

- **Certificate verification:** ECDSA on P-256, P-384 and P-521
  with SHA-256, SHA-384 or SHA-512; Ed25519; RSA PKCS#1 v1.5 and PSS,
  2048 to 8192 bits; ML-DSA.
- **Private keys:** RSA in PKCS#1 or PKCS#8; ECDSA in SEC 1 or
  PKCS#8; Ed25519 and ML-DSA in PKCS#8.
- **Session tickets:** sealed with ChaCha20-Poly1305, under a key
  rotated every six hours.

## AES-CCM

The CCM suites are for the constrained-device profiles that ask for
them, IEEE 2030.5 and RFC 7925 among them; nothing on the open web
negotiates them, so none is a default. A program that needs them
adds them to the provider it builds its configuration from:

```rust,ignore
use rustls_scytale::cipher_suite;

let mut provider = rustls_scytale::DEFAULT_PROVIDER;
provider.tls12_cipher_suites.to_mut().extend([
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
]);
```

- **The 16-byte-tag suites** are as strong as the defaults, and are
  in `ALL_TLS13_CIPHER_SUITES` and `ALL_TLS12_CIPHER_SUITES`.
- **The CCM-8 suites** carry an 8-byte tag, so a forged record
  succeeds with probability 2^-64 a try rather than 2^-128. TLS
  ends the connection at the first failure, which is why the
  profiles accept it. They are in no list: a program gets one only
  by naming it, never by taking a whole list. A server that adds
  one accepts it from any client that asks for it first; a server
  that wants it only as a last resort sets
  `ServerConfig::cipher_suite_selector` to `PreferServerOrder` and
  puts it last.
- **Kernel TLS** cannot take a CCM connection: rustls has no form
  for CCM keys to be handed on in, so extracting them is refused.

## Where it differs

- **ECDSA signatures are deterministic** (RFC 6979): the nonce is
  derived from the key and the message digest, with HMAC over the
  signing hash (SHA-256 for P-256, SHA-384 for P-384, SHA-512 for
  P-521), so a weak or failed random source cannot expose the key.
- **ML-DSA is preferred**, so a peer that holds an ML-DSA
  certificate beside a classical one is asked for the post-quantum
  one; a peer with one certificate signs with it whatever the
  order. rustls gives a provider no way to offer a scheme for TLS
  1.3 only, so a TLS 1.2 server's request for a client certificate
  lists ML-DSA too.
- **An RSA key must be `rsaEncryption`.** An `id-RSASSA-PSS` key is
  refused: its certificate's parameters would not match the public
  key rustls compares it against. An `rsaEncryption` key signs PSS.
- **Not FIPS validated.** Every `fips()` says so.
- **Randomness** is a CTR_DRBG seeded from the system for each
  request, so no generator state outlives a call to be copied by a
  `fork` or a virtual machine snapshot.

## Which rustls

The version number is scytale's, since the two are released
together, so it says nothing about rustls. This table does:

| rustls-scytale | rustls |
| --- | --- |
| 0.9 | 0.24.0-dev.1, pinned exactly |

A new rustls minor version arrives in a new rustls-scytale minor
version, and a row here says so.

## How it is tested

- Unit tests against published vectors: RFC 5869 for HKDF, RFC 8439
  for ChaCha20-Poly1305, and RFC 9001 for QUIC. The TLS 1.2 PRF and
  HPKE are scytale's, checked there against the IETF and ACVP
  vectors and the CFRG's.
- Full handshakes with this provider on both ends, over certificates
  and keys OpenSSL made (`tests/data/generate`): every suite with
  every key type, every key exchange group, client authentication
  with every key form, resumption.
- `scripts/test-rustls-downstream` in the scytale repository runs
  rustls's own API suite with this crate as the provider, rustls's
  HPKE test against the RFC 9180 vectors and against aws-lc-rs both
  ways, and BoGo, Encrypted Client Hello included, with no failures.
- `scripts/test-openssl-interop` connects this crate to OpenSSL
  over every suite it has, both ways, and over SECP384R1MLKEM1024
  where the OpenSSL has it (3.5 and later). BoGo cannot reach the CCM
  suites, since BoringSSL has none; here another implementation
  reads every record this one writes.
- Both scripts run in CI on every push.

## Licence

BSD-2-Clause, as scytale.
