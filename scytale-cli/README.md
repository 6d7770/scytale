# scytale-cli

The [scytale](https://crates.io/crates/scytale)
command line interface, for scripting and interactive use.

```sh
cargo install scytale-cli
```

installs a binary called `scytale`. It has one subcommand per module
of the library, names the algorithm on every call, takes its keys
and other bytes in a form that cannot be misread, streams where the
algorithm allows it, and does no cryptography of its own: every
operation is the library's, and the tool only carries bytes to it
and back.

## What it does

| Command | Does | Algorithms |
| --- | --- | --- |
| `scytale hash` | a digest of each input, `sha256sum` style | SHA-1, SHA-2, SHA-3, SHAKE, cSHAKE |
| `scytale mac tag` / `verify` | a tag over the input, or a check of one | HMAC, CMAC, KMAC, Poly1305 |
| `scytale aead encrypt` / `decrypt` | authenticated encryption, tag after the ciphertext | AES-GCM, AES-GCM-SIV, AES-CCM, AES-XPN, ChaCha20-Poly1305 |
| `scytale cipher encrypt` / `decrypt` | the unauthenticated modes | AES-ECB, -CBC, -CTR, -CFB, -OFB, -XTS, ChaCha20, FF1, FF3-1 |
| `scytale cipher wrap` / `unwrap` | key wrapping | AES-KW, AES-KWP |
| `scytale kdf hkdf` / `pbkdf2` / `tls12` | keys from keying material, from a password, or as TLS 1.2 derives them | HKDF, PBKDF2, TLS 1.2 PRF |
| `scytale key generate` / `public` / `show` | key files, as PEM | Ed25519, X25519, P-256, P-384, P-521, RSA, ML-KEM, ML-DSA, SLH-DSA |
| `scytale sig sign` / `verify` | signatures | Ed25519, ECDSA, RSA-PSS, RSA PKCS#1 v1.5, ML-DSA, SLH-DSA |
| `scytale kex agree` | a shared secret | X25519, ECDH |
| `scytale kem encapsulate` / `decapsulate` | a shared secret carried in a ciphertext | ML-KEM |
| `scytale pke encrypt` / `decrypt` | a short message under a public key | RSA-OAEP |
| `scytale random` | bytes from the system-seeded generator | CTR_DRBG |
| `scytale list` | every algorithm name, for a script to check | |

The algorithm is the operation: it is the first word after the verb
on every call, never an option and never defaulted, so a script says
what it does. `scytale list cipher`, `scytale list aead` and so on
print the names each command takes, `scytale list aead --long` what
each takes with it, and `--help` on any subcommand says what it
needs.

## Examples

Encrypt a file to a key held in a file, with a header authenticated
alongside it, and decrypt it again:

```sh
scytale random 32 --raw -o session.key
scytale random 12 > nonce.hex

scytale aead encrypt aes-256-gcm -k file:session.key \
    -n hex:$(cat nonce.hex) --aad str:v1 report.pdf -o report.sealed
scytale aead decrypt aes-256-gcm -k file:session.key \
    -n hex:$(cat nonce.hex) --aad str:v1 report.sealed -o report.pdf
```

Sign a release with a post-quantum key and check the signature:

```sh
scytale key generate ml-dsa-65 -o release.pem
scytale key public release.pem -o release.pub
scytale sig sign ml-dsa-65 -k release.pem release.tar -o release.sig
scytale sig verify ml-dsa-65 -p release.pub -s file:release.sig \
    release.tar && echo verified
```

Agree a key with a peer and derive session keys from it:

```sh
scytale key generate x25519 -o me.pem
scytale key public me.pem -o me.pub             # send this
scytale kex agree x25519 -k me.pem -p peer.pub --raw -o shared.bin
scytale kdf hkdf sha256 --ikm file:shared.bin --salt str:session-1 \
    --info str:encrypt --length 32
```

Interoperate with `openssl enc`, which pads CBC with PKCS#7 as this
does by default:

```sh
openssl enc -aes-128-cbc -K $KEY -iv $IV < plain > cipher
scytale cipher decrypt aes-128-cbc -k hex:$KEY --iv hex:$IV \
    --padding pkcs7 < cipher
```

Format-preserving encryption of card numbers, one per line, under a
tweak:

```sh
scytale cipher encrypt ff1-aes-256 -k file:fpe.key \
    --tweak str:cards-2026 < numbers.txt
```

## How values are written

Every option that carries bytes -- a key, IV, nonce, tag, salt,
signature or label -- is written with a prefix that says how to read
it, and never bare:

| Form | Meaning |
| --- | --- |
| `hex:00ff..` | hex, either case; no `0x`, no separators, an even count of digits |
| `file:PATH` | the raw bytes of the file, all of them |
| `fd:N` | the raw bytes read to the end of descriptor N, for `3< keyfile` |
| `env:NAME` | the variable's value, as hex |
| `str:TEXT` | the text itself; for additional data, labels, salts and contexts, refused for a key |

The algorithm fixes the length of a key, an IV or a nonce
(`aes-128-gcm` takes 16 bytes of key, `aes-256-xts` 32 in each of
`--key` and `--tweak-key`), and a value of another length is refused
with both lengths in the message and none of the bytes. Nothing is padded or cut to fit. `hex:` on a
command line is visible to every process on the machine through `ps`
and stays in the shell's history, so a key is better given as
`file:` or `fd:`; `hex:` is there for the script that already holds
one.

Key files are PEM: `PRIVATE KEY` (PKCS#8) and `PUBLIC KEY`, which is
what `openssl` and everything else write, and
the bare `RSA PRIVATE KEY`, `RSA PUBLIC KEY` and `EC PRIVATE KEY`
forms are read too. A command that takes a key file reads the
algorithm out of the file, so nothing is named twice. A file that
`generate` writes is created readable by its owner alone, as is any
file a secret is written to with `-o`.

## Behaviour a script can rely on

- Input is standard input, or the file named last; output is
  standard output, or `-o FILE`.
- Digests, tags, random bytes, shared and derived secrets are hex
  with a newline; ciphertext, signatures, wrapped keys and PEM are
  raw bytes. `--hex` and `--raw` turn either into the other on every
  command that writes bytes.
- Authenticated encryption appends the 16-byte tag to the
  ciphertext, and `--tag-length` shortens it where the construction
  allows. Decryption reads the whole input and writes nothing until
  the tag has checked; a message that fails leaves standard output
  empty.
- The stream modes, and GCM and ChaCha20-Poly1305 encryption, run a
  chunk at a time, so a pipe of any length goes through in fixed
  memory. The block modes take `--padding pkcs7` or `--padding
  none`, and say so if neither is given.
- ECDSA signatures are DER, as `openssl dgst` writes them, or
  `r || s` with `--raw-ecdsa`. Ed25519, ML-DSA and SLH-DSA
  signatures are the fixed-width bytes their standards define.
- A signature scheme is named in full, `ecdsa-sha256`,
  `rsa-pss-sha256`, `rsa-pkcs1-sha512`, and the key file must hold a
  key for it; one that does not is refused with what it holds.
- Exit status is 0 on success, 1 when a tag, signature or padding
  did not verify, 2 when the request could not be carried out as
  asked -- an unknown name, a value in the wrong form, a key of the
  wrong length -- and 3 for anything else, such as a file that would
  not open. Errors go to standard error as `scytale <command> <verb>
  <algorithm>: what is wrong; what would be right`, name the option
  concerned and the lengths or names involved, suggest the nearest
  algorithm name for one that is not known, and never contain key
  material. A closed standard output ends the run quietly with
  status 0.
- There is no configuration file and nothing is read from the
  environment except the variable an `env:` value names. The tool
  needs no privileges.

## What it will not do

Nothing here authenticates a message unless `aead` or `mac` is
asked to. The `cipher` modes are for a protocol that brings its own
MAC, a disk, a key to wrap, or a format to preserve; a script that
needs to know a message is what was encrypted wants `aead`. The
format-preserving modes, like the library's, are not constant time
and say so. Private keys are written unencrypted; keep them where
`0600` is enough, or wrap them with `aes-256-kwp` under a key that
is.

## Building

```sh
cargo install scytale-cli
```

or, from a checkout of the repository, `cargo install --path
scytale-cli`. The crate depends on scytale, zeroize and clap, and
builds wherever they do; the tests run the binary, and compare with
`openssl` when it is on the path.

The manual is `scytale.1` beside this file, which `cargo install`
does not place, and [`scytale.1.md`](scytale.1.md) is the same text
rendered for reading here. To read the manual in place, `man -l
scytale.1`; to install it:

```sh
install -m 644 scytale.1 /usr/local/share/man/man1/
```

`--help` on every subcommand ends with the value syntax and the exit
codes, so a call can be got right without it.

## License

BSD-2-Clause, as scytale.
