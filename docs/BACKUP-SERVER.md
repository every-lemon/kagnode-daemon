# Backup Server implementation status

Status: development source only. No released or deployed backup-server runtime.
The source remains in the 5.0.x series. Existing `.kndb` recovery is unchanged.

## Implemented primitives

`crates/backup-format` defines `kagnode-dbackup/v2`, 4 MiB plaintext chunks,
compression before age encryption, SHA-256 ciphertext references, an encrypted
file catalog, incremental ciphertext reuse and bounded recovery into a new
private directory. The cache is private agent state and must never be uploaded.
Changing the recipient invalidates the cache. Inputs must already be consistent
adapter-created snapshots; this API is not a live-database backup adapter.

The crate also validates legacy `kagnode-dbackup/v1` split manifests. Legacy
stream decryption and tar restoration are still to be integrated; validation
alone is not a complete legacy restore implementation.

`src/backup_service` implements local repository primitives: one owning process,
private files, storage-directory identity checks, approved enrollment challenges,
Ed25519 verification, persistent nonce replay rejection, upload leases, resumable
bounded chunks, ciphertext verification, snapshot commit receipts, monthly
transfer counters, retention protections, restore leases and shared-object GC.
Snapshot deletion is recorded as a tombstone. Stored signatures bind manifests;
file contents and filenames remain in encrypted objects.

Administrative methods are internal library APIs. Their `actor` argument is an
audit label, not authentication. A separately authenticated administration plane
must authorize them before use. No remote endpoint exposes these methods yet.
Signing and replay checks do not substitute for TLS server authentication or
complete approved site/node enrollment. The server does not accept recovery keys.

The readiness policy refuses unsafe or stale nodes, uses sustained busy/ready
hysteresis and supports throttling after the selected deferral. Capacity estimates
assume no compression or sharing savings. Policy setup must explicitly choose
interval, recovery goal and retention; there is no automatic schedule.

## Checks

Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked --
-D warnings` and `cargo test --workspace --locked`. New tests use temporary,
synthetic fixtures and ephemeral keys. They cover encrypted recovery, recipient
rotation, corruption rejection, nested paths, bounded decompression, partial
uploads, process reopen, replay, revocation, snapshot identity, transfer caps,
reserve refusal, active-restore protection and retained shared objects.

These are local unit/integration checks, not disposable-OS qualification.
Do not enable the Backup Server role or advertise production recovery based on
these results.

## Unfinished integration and qualification

- Supervised unprivileged backup-server process and exclusive-role installation.
- Approved remote enrollment, TLS, server receipts, complete identity lifecycle,
  signed wire requests, replay/rate bounds and node-to-all-server transfer jobs.
- Durable scheduling, administrator APIs under `/api/v1/backups/` and
  `/api/v1/backup-server/`, Core pages and terminal controls.
- Measured bandwidth, aggregate/time-window throttling, audited cap overrides,
  accounting for restore downloads, recovery reminders and multi-server K state.
- Complete v1 recovery, dedicated restore runner, adapter-consistent snapshots,
  operational logs and coordinated SQLite PITR for Daemon, Passwords, Mail and PM.
- Index-loss reconciliation, orphan/expired-partial cleanup, crash injection at
  every filesystem/SQLite boundary, automatic retention and volume replacement.
- RAID/SMART/scrub reporting, restore drills, Debian 13/Ubuntu 24.04 qualification,
  permissions review, release, deployment and rollback verification.

No plaintext application data, production credentials or recovery identities
belong in this repository or its test evidence. HTTP Boot image builds, Pi UI
updates, Media deployment and hardware qualification remain outside this work.
