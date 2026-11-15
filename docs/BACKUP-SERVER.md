# Backup Server implementation status

Status: development source only. No released or deployed backup-server runtime. A supervised experimental process
and authenticated transport are available in development source.
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

The `kagnode-backup-server` binary refuses root execution. The Daemon supervises
it separately from the optional web dashboard and terminal client, restarts it
after failure, and records failures without taking down monitoring. Repository
and controller state must be disjoint. Supervision refuses known product and
legacy-product directories on a Backup Server node. Installer-wide role
activation and enforcement are not finished.

Remote requests use mutual TLS plus separately signed, server/site-bound requests.
Enrollment requires a short-lived, one-use administrator approval bound to the
node signing key and its client-certificate fingerprint. Revocation blocks further
requests; persistent nonces reject replay. Requests, connections, upload chunks
and response sizes are bounded. The listener has no plaintext HTTP mode.

Remote nodes have only enrollment, upload, lease and own-status operations.
They cannot call retention, deletion or restore-attestation methods. Administrative
operations use an owner-only Unix socket. Daemon exposes status and action routes
under `/api/v1/backup-server/`, protected by its local administrator session,
origin/CSRF checks and recent authentication. The CLI exposes the same control
socket as `kagnode backup-server`. No recovery keys are accepted by the server.
Administrative library actor arguments remain audit labels, not authentication;
new integrations must retain the control-plane authorization boundary.

The outbound Rust agent verifies the configured CA/hostname, refuses redirects
and plaintext URLs, signs requests and resumes partial uploads. Repeated completed
uploads return the original ciphertext receipt. `push_all` reuses one immutable
manifest for every configured server and records independent failures. It does
not yet calculate K health or implement a durable transfer scheduler.

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

The transport tests generate temporary certificates and synthetic encrypted
snapshots. They exercise real TLS enrollment/upload, recovery from server-held
ciphertext, client-certificate binding, missing-certificate refusal, revocation,
retries, local administration separation, session/CSRF enforcement and process
restart without a dashboard. The unprivileged lifecycle path runs when the test
process is non-root; on a root development host it tests refusal to start as root.

`tests/backup-qa.Containerfile` prepares disposable Debian 13 or Ubuntu 24.04
userspaces with OpenSSL for fixture certificates. Run the backup test binaries
as UID 1001, with no capabilities, a read-only root, an isolated network,
384 MiB RAM and one CPU. Tests must use only synthetic data and temporary keys.
Container tests are limited userspace/process evidence; they do not qualify disk
failure behavior, application-native adapters, SQLite PITR or production restores.
Do not enable a live Backup Server role based on these checks alone.

## Unfinished integration and qualification

- Reviewed exclusive-role installation, legacy installer enforcement and native
  service sandbox/volume permissions for the separate worker.
- Automated certificate lifecycle, signed portable server receipts, node/site
  enrollment management and durable node-to-all-server transfer jobs.
- Durable scheduling and `/api/v1/backups/` job APIs, Core pages and TUI controls.
  Existing backup-server CLI/API controls require a separately configured worker.
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

## Experimental process configuration

The daemon reads a private, service-owned `backup-server.json` in its controller
state directory only when explicitly present. The schema has `repository`,
`listen`, `certificate`, `private_key`, `client_ca` and `control_socket` fields.
The control socket must be `run/backup-server.sock` under the controller. TLS keys
and configuration must be regular, owned, private files; certificates and the CA
must not be writable by other users. Install both executables alongside each
other in an administrator-controlled directory for supervision.

Initialize an empty synthetic repository with the unprivileged binary's `init`
command and an explicit policy file. Policy requires a schedule interval, recovery
point goal and retention; this does not start a schedule. The intended reserve
default is 20 GiB with a 5% usable-capacity floor, maximum deferral 24 hours,
bandwidth share 25%, and minimum verified copy count one. Real deployments still
require the unfinished reviewed installer and recovery qualification.

`kagnode backup-server status`, `snapshots`, `approve`, `revoke`, `policy`, `pin`
and `delete` operate through the local socket. Approval prints an enrollment token
for the approved node; do not save its output in diagnostics or handoffs. Deletion
requires the exact `delete node/snapshot` confirmation and still refuses protected
snapshots. There is no command that uploads recovery identities.

TLS implementation uses [rustls client-certificate verification](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html)
and [Hyper connection serving](https://docs.rs/hyper-util/latest/hyper_util/server/conn/auto/struct.Builder.html).
