# Reviewed native installer API — draft

This Rust backend draft unifies fresh protected and owner-mode installation. It is
not legacy Go adoption, a production qualification or permission to install on a
live host. Keep the existing Go Core/updater argv and `/usr/bin/kagnode` unchanged.
The API rejects existing installations rather than guessing that missing Rust
state means there is no application data. Native execution and independent
security review remain gates.

## Exact API for terminal/frontend integration

Use the root-local Rust API in `kagnode_daemon::native_install`:

```rust
pub struct Options {
    pub profile: Profile,
    pub web: bool,
    pub origin: String,
}
pub enum ProtectionChoice {
    Protected { account: String },
    Owner { actual_owner_uid: u32 },
}
pub enum Protection<'a> {
    Protected { account: &'a str, password: &'a str },
    Owner { actual_owner_uid: u32 },
}
pub fn plan(options: Options, choice: ProtectionChoice) -> Result<Plan>;
pub fn apply_reviewed(
    reviewed: &Plan,
    protection: Protection<'_>,
    expected_plan_sha256: &str,
) -> Result<serde_json::Value>;
pub fn recovery_status() -> Result<serde_json::Value>;
```

These are **root-only local installer functions**, not socket actions. Do not add
a Manager-facing RPC around them or accept an asserted UID from a normal session.
`Protection` deliberately implements neither `Debug` nor `Serialize`. Keep the
borrowed password in zeroizing frontend storage; never put it in arguments, URLs,
plans, journal, audit, errors or a log. The plan contains the normalized account,
protection mode and verified actual owner UID, not a password or password hash.
Password hashing completes before native mutations and outside the store mutex.

The existing `install::apply(email, password, profile, web, origin)` signature stays
as a checked compatibility wrapper around the protected branch of this API. New
callers must retain the displayed explicit plan and pass its hash to
`apply_reviewed`; the old generic `install::plan` is only profile presentation and
is not the native machine-state approval record.

A returned `Plan` contains schema/version, options, protection, source executable
identity/hash, fixed service UID/GID, exact rendered units, relevant machine state,
`admin_enabled:false`, `legacy_adoption:false`, and `plan_sha256`. Apply recomputes
its canonical hash and repeats host preflight before changing anything. Source
pinning is the exact running root-owned executable bytes, inode and metadata.
Existing binaries do not carry attested Git provenance; this API does **not**
invent a commit from environment variables or substitute for signed release
verification. The installation caller must independently verify the candidate's
signed source/binary record before native qualification or activation approval.

## Fresh-install policy

- Ubuntu 24.04 / Debian 13 GNU Linux amd64 or arm64; fixed managed paths and
  executable/argument vectors, no shell or free-form commands.
- Root-owned protected ancestry, independent bounded regular files, nonblocking
  no-follow reads, copied-byte hashes, exact ELF target and no existing command,
  state, service, enabled link or unsupported unit override. Existing reserved
  service user/group also requires adoption/recovery review.
- Choose one currently unused UID/GID pair from the fixed system range 950–999.
  The exact pair and exact rendered broker UID are in the reviewed plan; groupadd
  and useradd receive that pair explicitly. No useradd allocation surprise or
  service-UID substitution for the owner.
- Owner mode verifies an existing local OS account through NSS, accepts root or
  a regular login account, rejects service accounts, records that exact UID,
  creates one implicit Operator and sets dashboard/admin off. This native draft
  currently admits **root owner UID0 only**: regular owners cannot traverse the
  service-owned0700 controller directory to its private socket. Non-root owner
  choices fail before mutation until a separately reviewed owner-only transport
  is implemented and qualified; do not loosen Store/directory permissions. The
  lower-level generic owner initializer retains its existing actual-UID rule.
  The native installer never consults
  `SUDO_UID` or untrusted environment identity. Generic `roles::init_owner` still
  requires UID equal to the initializing process; only the private root installer
  has an additional fresh-private-store initializer.
- Protected mode creates the first Operator and independently sets admin off,
  even if the optional dashboard was selected. Existing state cannot be reset or
  downgraded into owner mode. The established enable-protection and root recovery
  paths remain separate.
- Initialize state privately before assigning it to `kn-daemon`; only the newly
  created controller directory/files are chowned. Owners, Managers and Viewers do
  not gain direct store access. The broker remains a separate root service.
- Copy/reuse an exact versioned native payload, create the fresh fixed entry
  links, install only the reviewed units, then start the new Daemon/broker and
  check their active state. Existing application services/traffic are untouched.

## Journal and failures

The private root-owned `installation.json` records the reviewed plan, actor,
service/owner identities, pending step, completed steps and created-file hashes.
Every mutation phase is journalled and fsynced before execution; writes use a
new-file/atomic-rename/directory-fsync protocol. A failed or timed-out operation is
`needs_recovery` with a generic error code and the unresolved pending step.
Credential material is not journalled. Fixed native engines have a cleared
environment, sealed inherited descriptors and a bounded process group.

`recovery_status` is inspection only. It does not blindly retry user creation,
service activation, delete identities or remove controller data. Interrupted
journal temp files remain for inspection. Fully reviewed legacy-copy/adoption and
rollback are a separate follow-up; do not describe this inspection contract as an
implemented automatic rollback.

Known errors include `Native installation requires root`, `Native installation
plan hash mismatch`, `Installation identity differs from reviewed plan`, `Native
installation state changed; review a new plan`, `Existing installation retained`,
`Reserved service identity already exists`, `Origin cannot contain systemd percent
specifiers`, and `Unprotected owner mode requires dashboard and web administration
off`. Unexpected OS errors stay errors; do not report success after a failure.

## Terminal/native boundary

The current root CLI demotes to the controller service UID before the terminal
login gate, while an Operator gate still directly opens Store. That integration
is not fixed by this backend draft. Do not record owner UID as the service UID,
relax Store ownership, spoof a peer UID or remove the owner/session checks to hide
it. Claude owns the terminal/client change. Root/backend headless installation can
be qualified separately; complete native terminal sign-in remains unverified
until it passes as the real owner against a differently owned service. Regular
native owners additionally need a safe owner-only transport; that is a separate
blocker from terminal demotion and is explicitly gated rather than described as
working merely because a UID can be stored.

## Backend automation CLI

`kagnode native-setup plan --account operator@fixture.invalid --profile light`
(or `--owner-uid 0`, mutually exclusive with account) emits the explicit plan.
Create the plan file privately with umask0077; retain the displayed hash outside
that file for the reviewed apply. `kagnode native-setup apply --plan ABS_PLAN
--expected-sha256 HASH --password-stdin` reads only a bounded pipe or private
root-owned input file. Owner mode omits `--password-stdin`. The secret is never a
command argument. `kagnode native-setup recovery` inspects the existing receipt.
All three commands execute before unrelated terminal/store privilege dropping,
require real root, use fixed native paths and do not honor a custom global
`--root`. They are backend automation commands, not a replacement terminal UI.
