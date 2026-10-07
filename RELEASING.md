# Releasing

The four crates, `scytale`, `scytale-ring`, `rustls-scytale` and
`scytale-cli`, share one version and go out together. A release is
one commit that bumps the version, one tag, and four `cargo publish`
calls in dependency order. The version changes only here, at release; a feature or an API
change does not carry a bump with it.

## 1. Decide the version

- The API grew or changed: bump the minor (`0.8.0` to `0.9.0`).
  Before 1.0 a minor is the breaking step, and anything a caller
  could write against the old version that the new one refuses is a
  break.
- Only fixes: bump the patch.

The shim, the provider and the tool depend on the library by
`version = "0.N"`, so a minor bump is what lets them reach a new
library API; a patch bump needs no change there.

`rustls-scytale` goes out only while its `rustls` dependency is a
release: it is pinned exactly to `=0.24.0-dev.1` now, and each
development release of rustls may change the provider traits. Until
rustls 0.24.0, leave it out of the publish in step 6.

## 2. Bump every place the version lives

- `Cargo.toml` (workspace): `version`.
- `scytale-ring/Cargo.toml`, `rustls-scytale/Cargo.toml` and
  `scytale-cli/Cargo.toml`: the `version` in their
  `scytale = { path = ..., version = "0.N" }` lines, on a minor bump.
- `README.md` and `scytale-ring/README.md`: the `ring = { package =
  "scytale-ring", version = "0.N" }` example lines, and the "Which
  ring" table in the shim's README, which gains a row when the ring
  API it presents changes and otherwise has its versions checked.
- `README.md` and `rustls-scytale/README.md`: the
  `rustls-scytale = "0.N"` lines, and the "Which rustls" table in the
  provider's README, kept the same way.
- `scytale-cli/scytale.1`: the `.TH` line's date and `scytale 0.N`.
  `cargo test -p scytale-cli` fails if this is missed. Then
  `scripts/man-md` to regenerate `scytale.1.md`.
- `Cargo.lock`: `cargo update -w` records the new versions.

`grep -rn '0\.OLD' --include=Cargo.toml --include='*.md'
--include='*.1' . | grep -v target` finds anything this list has
forgotten.

## 3. Check what the READMEs claim

- The ACVP and Wycheproof case count in `README.md` ("The corpus is
  N files holding M cases") is hand-maintained and counts the cases
  the drivers run, once per suite, after every documented skip.
  Recompute it if a suite was added or removed: for a suite that
  skips nothing the file's AFT total is the number; for one that
  skips groups, raise its minimum-count assertion and read the true
  count from the failure.
- Any speed figure in `README.md` or the shim's README that a change
  this release could have moved: rerun `scripts/bench` for it on the
  reference machine, or dispatch `bench.yml` for another
  architecture, and update `scytale/benchmarks/`. No figure goes out
  that was not measured on the code being released.
- The algorithm tables, if a primitive was added: `README.md`,
  `scytale/src/lib.rs`, `SECURITY.md`, the shim's README, and the
  tool's README and manual.

## 4. Run everything

```sh
scripts/ci-check                 # the style job, as CI runs it
cargo test-extended              # every test, ignored ones included
scripts/test-all-arches          # the foreign architectures under cross
scripts/test-ring-downstream     # rustls and webpki on scytale-ring
scripts/test-rustls-downstream   # rustls's tests and BoGo on the provider
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

Then the packaging. Only the library's can be tried before the
release: the shim and the tool depend on the new library version,
which crates.io does not have until step 6, and even `--no-verify`
resolves the dependency there.

```sh
cargo publish --dry-run -p scytale
cargo package -p scytale-ring --list
cargo package -p rustls-scytale --list
cargo package -p scytale-cli --list
```

## 5. Commit, tag, push

One commit, subject `scytale 0.N.M: <what the release is>`, body
saying what changed for a user of each crate, as the history has it.
Then:

```sh
git tag -a v0.N.M -m "scytale 0.N.M"
git push && git push --tags
```

Wait for CI on the tag to pass on every job before publishing;
`bench.yml` is not part of that gate.

## 6. Publish, in dependency order

```sh
cargo publish -p scytale
cargo publish -p scytale-ring
cargo publish -p rustls-scytale
cargo publish -p scytale-cli
```

Each waits on the one before: crates.io must have the library before
the shim's, the provider's and the tool's verify builds can resolve
it. A failed publish after the first is redone once the first is
visible; nothing needs unpublishing.

## 7. Afterwards

- The tag is the release; GitHub's release pages have not been used,
  and the commit body is where the notes are.
- `docs.yml` publishes the library's documentation from `main`; check
  https://docs.rs/scytale built the new version.
- `TODO` records what the release closed and what it opened.
