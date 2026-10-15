# Releasing

The four crates, `scytale`, `scytale-ring`, `rustls-scytale` and
`scytale-cli`, each have their own version and are released on their
own. A release is one commit that bumps the version of each crate
going out, a tag for each, and a `cargo publish` for each, the
library first. The version changes only here, at release; a feature
or an API change does not carry a bump with it.

Tags name the crate: `scytale-v0.10.0`, `scytale-ring-v0.10.1`. Each
tag names exactly one crate and version, and `scytale-v*` matches only
the library's. Releases up to `v0.9.0` were of all four crates
together under one version, and are tagged `v0.N.M`.

## 1. Decide what goes out, and at which version

A crate goes out when its own code changed since its last tag:

```sh
git log --oneline scytale-ring-v0.10.0.. -- scytale-ring
```

For each such crate:

- It broke: bump the minor (`0.10.3` to `0.11.0`). Before 1.0 a minor
  is the breaking step, and anything a caller could write against the
  old version that the new one refuses is a break.
- Otherwise, additions and fixes alike: bump the patch (`0.10.0` to
  `0.10.1`). A user then gets the release from `cargo update`, with
  no edit to a manifest.

The shim, the provider and the tool name the oldest library release
that has everything they use: `scytale = { path = ..., version =
"0.N.M" }`. A crate that starts using something added in a library
patch release raises that requirement, and the library goes out first
or in the same release. A new library minor breaks the requirement in
every dependant at once: cargo refuses to build the workspace until
each names the new minor, and each then goes out too, so that its
users get the new library.

`rustls-scytale` pins its `rustls` exactly while rustls 0.24 is a
development release, since each one may change the provider traits,
and its own version is then a pre-release carrying the same suffix:
`0.10.0-dev.2` for rustls `=0.24.0-dev.2`, `0.10.0-dev.2.1` for a fix
against the same rustls, `0.10.0-dev.3` when it moves to the next.
Cargo picks a pre-release only when it is named, so nobody gets one
unasked. It becomes plain `0.10.0` with rustls 0.24.0, and takes the
rules above from then on. Release it only for the rustls development
release that is current.

## 2. Bump every place the version lives

For each crate going out:

- Its `Cargo.toml`: `version`.
- A library release: the `version` in the dependants'
  `scytale = { path = ..., version = "0.N.M" }` lines, where the
  requirement no longer accepts it or a dependant needs what it adds.
- `scytale-ring`: the `ring = { package = "scytale-ring", version =
  "0.N" }` example line in `scytale-ring/README.md`, on a minor bump,
  and the "Which ring" table in the shim's README, which gains a row
  when the ring API it presents changes and otherwise has its
  versions checked.
- `rustls-scytale`: the `rustls-scytale = "0.N"` line in
  `rustls-scytale/README.md`, on a minor bump, and the "Which
  rustls" table in the provider's README, kept the same way.
- `scytale-cli`: the `.TH` line's date and `scytale 0.N` in
  `scytale-cli/scytale.1`. `cargo test -p scytale-cli` fails if this
  is missed. Then `scripts/man-md` to regenerate `scytale.1.md`.
- `Cargo.lock`: `cargo update -w` records the new versions.

`grep -rn '0\.OLD' --include=Cargo.toml --include='*.md'
--include='*.1' . | grep -v target` finds anything this list has
forgotten.

## 3. Check what the READMEs claim

- The ACVP and Wycheproof case count in `scytale/README.md` ("The
  corpus is N files holding M cases") is hand-maintained and counts
  the cases the drivers run, once per suite, after every documented
  skip. Recompute it if a suite was added or removed: for a suite
  that skips nothing the file's AFT total is the number; for one that
  skips groups, raise its minimum-count assertion and read the true
  count from the failure.
- Any speed figure in `scytale/README.md` or the shim's README that a
  change this release could have moved: rerun `scripts/bench` for it
  on the reference machine, or dispatch `bench.yml` for another
  architecture, and update `scytale/benchmarks/`. No figure goes out
  that was not measured on the code being released.
- The algorithm tables, if a primitive was added: `scytale/README.md`,
  `scytale/src/lib.rs`, `SECURITY.md`, the shim's README, and the
  tool's README and manual.

## 4. Run everything

Whichever crates go out, every check runs: the dependants are the
library's most demanding tests.

```sh
scripts/ci-check                 # the style job, as CI runs it
cargo test-extended              # every test, ignored ones included
scripts/test-all-arches          # the foreign architectures under cross
scripts/test-ring-downstream     # rustls and webpki on scytale-ring
scripts/test-rustls-downstream   # rustls's tests and BoGo on the provider
scripts/test-openssl-interop     # every provider suite against OpenSSL
```

The last needs Go, a C compiler and `cpp` for BoGo.

and the CI jobs that `test-extended` does not cover on the host:

```sh
for t in wasm32-unknown-unknown x86_64-unknown-none \
         aarch64-unknown-none riscv64gc-unknown-none-elf; do
    RUSTFLAGS="-D warnings" cargo build -p scytale --target $t
done
for t in i686-unknown-linux-musl wasm32-wasip1; do
    cargo clippy --workspace --all-targets --profile test \
        --target $t -- -D warnings
done
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Then the packaging. Packaged together, each crate is built against
the library as it will be published rather than the one on
crates.io, which does not have a new library version until step 6:

```sh
cargo package --exclude-lockfile -p scytale -p scytale-ring \
    -p rustls-scytale -p scytale-cli
```

A dependant going out without a library release must also build
against the library crates.io already has, which is what its users
get:

```sh
cargo package -p scytale-ring
```

## 5. Commit, tag, push

One commit, subject naming each crate going out and its version
(`scytale 0.10.1, scytale-cli 0.10.2: <what the release is>`), body
saying what changed for a user of each. Then a tag for each crate:

```sh
git tag -a scytale-v0.N.M -m "scytale 0.N.M"
git push && git push --tags
```

Wait for CI on the release commit on `main` to pass on every job
before publishing; `bench.yml` is not part of that gate.

## 6. Publish, library first

```sh
cargo publish -p scytale
cargo publish -p scytale-ring
cargo publish -p rustls-scytale
cargo publish -p scytale-cli
```

Only the crates going out, in this order. crates.io must have a new
library before the shim's, the provider's and the tool's verify
builds can resolve it. A failed publish after the library's is redone
once the library is visible; nothing needs unpublishing.

## 7. Afterwards

- The tags are the release; GitHub's release pages have not been
  used, and the commit body is where the notes are.
- `docs.yml` publishes the library's documentation from `main`; check
  https://docs.rs/scytale built the new version.
- `TODO` records what the release closed and what it opened.
