# Rust Daemon candidate pipeline — draft, no publisher

The existing compatibility release builder still describes the historical Go CLI.
It is not a Rust Daemon build. Its automatic tag publisher is deliberately disabled
by this draft; its source/compatibility checks remain. No published tag or asset is
changed, and no new product version is declared by this work.

`kagnode-release` is a maintainer-only Rust builder/verifier. It produces signed,
explicitly **unqualified preview candidates**, never a production-eligible stable
release. There is no publish, install, activation, data migration or service command.
Claude's independent pipeline review, native protected/owner installation, legacy
adoption, real terminal sign-in and rollback qualification remain separate gates.
Passing a build or signature check does not satisfy them. Existing 5.0.3 Go release
assets must not be overwritten with these Rust candidates; a later real release
needs a reviewed new 5.0.x patch.

## Build and verify

From a clean committed current-source checkout, build the maintainer tool with
`cargo build --locked --bin kagnode-release`. Keep all workspace/cache/temporary
paths on the mounted data disk. Retain 20 GiB free plus the estimated 8 GiB next-build
budget; at least 2 GiB memory remains available. The tool stops and retains partial
work on budget/headroom, timeout, output or integrity failure. Do not clean around
its guards mid-build. Only one heavy build/test/VM should run on the host at once.

The builder takes `build --source ABS_SOURCE --work NEW_ABS_WORK --output
NEW_ABS_OUTPUT --target x86_64-unknown-linux-gnu --signing-fd N`. The inherited
read-only descriptor supplies the existing private signing identity; do not put
private material or credential paths in shell history, command arguments or logs.
The key stays outside source and payloads. It must match the existing Daemon
manager's Ed25519 public anchor, now recorded as `packaging/release-public.pem`.
No key generation, downloaded-key trust or verifier replacement is performed.

The source and output/work trees must be separate and protected. The source must
be clean and the sorted allowlist exactly equal `git ls-files`. Every source byte
and executable mode must match Git; links, special/runtime files, traversal and
private-key material are rejected. Source identity and file hashes are rechecked
between builds and before final output.

Two **absent, separate Cargo target directories** are built sequentially using
locked offline dependencies, two Cargo jobs, fixed epoch, no incremental compilation and
identical path-remapping flags for both target roots. Both real Rust executables
(`kagnode`, `kagnode-backup-server`) must have the declared ELF target and source
version and compare byte-for-byte. Cargo's own executable hardlinks are copied to
independent identical-byte files before admission. `build-observations.json` records
actual executable hashes even if equality fails; differing builds are not signed.

Normalized USTAR/gzip source and native archives and an inert Debian native payload
are generated twice, signed twice with deterministic Ed25519, and compared as full
file sets. Tar validation rejects unsafe/duplicate names, links, special files,
multiple top roots, count/size violations, truncated data and hidden trailing
members. Native attribution contains license texts from reachable production and
build-time Cargo dependencies; dev-only graph edges are excluded. First-party
workspace crates use the root's declared AGPL license where applicable.

The Debian package contains only versioned libexec payload and documentation.
It has **no** `/usr/bin/kagnode`, account creation, maintainer script, unit activation
or data migration. It cannot silently replace the retained Go updater command.
Native Ubuntu 24.04 amd64 execution is the initial target; a cross-target compile
never means target execution. RPM/native service support is not claimed.

`kagnode-release verify --directory ABS_OUTPUT` verifies the original signed manifest
bytes with the compiled existing anchor, exact native/source kinds and filenames,
all hashes/sizes, known metadata file set and checksum file. A public key shipped
beside an archive is not a new trust source. Duplicate JSON members are rejected.
The signed manifest records source/tree/epoch/toolchain/target, binary hashes and
`production_eligible:false`; no automatic-update eligibility contract is created.

## Qualification and review

Regression coverage includes dirty source, path/symlink/hardlink and reuse refusal,
wrong ELF/target, private/read-only signer descriptor, wrong/missing signature,
tampering, duplicate JSON, bounded timeout, archive attacks, license graph selection
and changed output bytes. Actual source-specific two-build and signed-package
proofs belong in the maintainer handoff, not a claim of stable native qualification.
The normal Rust CI tests this code and never has a production signing secret.

The root broker's logical actor binding, native owner service/terminal UID behavior,
legacy Go service argv preservation, real copy migration and rollback remain
unimplemented/unqualified separately. Do not enable capabilities or publish a
stable Rust release merely because this candidate pipeline passes.

Some locked upstream `.crate` distributions omit the full license texts.
`packaging/rust-license-sources.json` records the exact `.cargo_vcs_info` commits,
original Git blob IDs, public primary-source links and SHA-256 checksums for a small
corresponding-license subset. Unknown package versions/license changes fail closed.
The io_tee upstream has a dual-license grant only in README; this draft selects its
existing Apache-2.0 option, preserves that pinned README grant, and includes the
canonical full Apache text from a pinned SPDX source. This is explicit for review,
not invented permission or a change to the dependency's declared alternatives.
The native archive and Debian documentation both retain these license texts.
