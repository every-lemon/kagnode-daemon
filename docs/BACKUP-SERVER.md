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

The `kagnode-backup-server` binary refuses root execution and requires a distinct
controller UID. The dedicated systemd service owns its process lifecycle; Daemon
monitors the private socket and **never** falls back to a same-user network child.
Before starting Tokio the executable closes inherited descriptors above stderr
and re-executes with an empty environment. `NoNewPrivileges` is enforced in the
worker too. See `packaging/kagnode-backup-server.service` for the restricted
service template. No service is installed or enabled by this source change.
Repository and controller state must be disjoint. The controller must not give
the worker read access to its private state. Installer-wide role activation,
custom-path sandbox generation and real systemd qualification remain unfinished.

Remote requests use mutual TLS plus separately signed, server/site-bound requests.
Enrollment requires a short-lived, one-use administrator approval bound to the
node signing key and its client-certificate fingerprint. Revocation blocks further
requests; persistent nonces reject replay. Requests, connections, upload chunks
and response sizes are bounded. The listener has no plaintext HTTP mode.

Remote nodes have only enrollment, upload, lease and own-status operations.
They cannot call retention, deletion or restore-attestation methods. Administrative
operations use an owner-only Unix socket. Daemon exposes status and action routes
under `/api/v1/backup-server/`, protected by its local administrator session,
origin/CSRF checks and recent authentication. The generic `/actions` passthrough
is removed. Explicit POST routes are `approve`, `revoke`, `policy`, `pin`, `delete`
and `garbage-collection`; read-only snapshots use `GET snapshots/:node`.
All mutations except adding a pin require a one-use server confirmation from
`POST confirm` with a fresh local password. It expires after 60 seconds and is
bound to the session and exact serialized operation; supply it as
`X-Backup-Confirmation`. Failed or interrupted operations consume confirmation
and must be inspected before confirming again. No secret is placed in URLs. The CLI exposes the same control
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
worker identity separation. The old same-user child-restart fixture was removed
because that launch mode is no longer allowed. Systemd restart/sandbox enforcement
requires its own disposable VM qualification; it is not proven by a unit template. An opt-in `KAGNODE_PRIVILEGED_FIXTURE=1` test
runs only as root in a disposable namespace: it starts a numeric-UID worker,
checks empty environment and inherited-descriptor removal through `/proc`, and
verifies that the worker UID cannot read a different controller UID's directory.
Never enable this fixture in a live service or production test directory.

`tests/backup-qa.Containerfile` prepares disposable Debian 13 or Ubuntu 24.04
userspaces with OpenSSL for fixture certificates. Run the backup test binaries
as UID 1001, with no capabilities, a read-only root, an isolated network,
384 MiB RAM and one CPU. Tests must use only synthetic data and temporary keys.
Container tests are limited userspace/process evidence; they do not qualify disk
failure behavior, application-native adapters, SQLite PITR or production restores.
Do not enable a live Backup Server role based on these checks alone.

## Unfinished integration and qualification

- Reviewed exclusive-role installation, legacy installer enforcement and native
  service sandbox/volume permission qualification for the separate worker.
- Automated certificate lifecycle, signed portable server receipts, node/site
  enrollment management and durable node-to-all-server transfer jobs.
- Durable scheduling and `/api/v1/backups/` job APIs, Core pages and TUI controls.
  Existing backup-server CLI/API controls require a separately configured worker.
- Measured bandwidth, aggregate/time-window throttling, audited cap overrides,
  accounting for restore downloads, recovery reminders and multi-server K state.
- Complete v1 recovery, dedicated restore runner, adapter-consistent snapshots,
  operational logs and coordinated SQLite PITR for Daemon, Passwords, Mail and PM.
- Index-loss/orphan reconciliation, lease-row pruning, crash injection at
  every filesystem/SQLite boundary, automatic retention and volume replacement.
- RAID/SMART/scrub reporting, restore drills, Debian 13/Ubuntu 24.04 qualification,
  permissions review, release, deployment and rollback verification.

No plaintext application data, production credentials or recovery identities
belong in this repository or its test evidence. HTTP Boot image builds, Pi UI
updates, Media deployment and hardware qualification remain outside this work.

## Experimental process configuration

Daemon reads a private controller-owned `backup-server.json` only when explicitly
present. Its schema has `repository`, `listen`, `certificate`, `private_key`,
`client_ca`, `control_socket` and `controller_uid`. The controller configuration
is a non-secret path/UID descriptor; the service has its own copy at
`/srv/kagnode/backup-server/config.json`. Its repository is owned by
`kagnode-backup`, not the controller. `controller_uid` must match the unprivileged
Daemon and differ from the worker. A root-owned traversable parent (for example
0751) contains the worker's 0700 repository and 0600 credentials, so the controller
can inspect the repository owner without reading its contents. The socket is `/run/kagnode-backup/admin.sock`,
0660, in a worker-owned 0750 runtime directory. A dedicated
`kagnode-backup-control` group allows the controller to connect; peer UID checking
permits only that configured controller or root. Group access alone grants no
administration. The controller verifies the server peer UID against the reviewed
repository owner. Controller private state stays 0700 with its separate owner.

The unit template uses fixed example paths; administrators must review accounts,
volume ownership, executable location and inaccessible controller paths before
installation. It requires Linux `close_range`; unsupported hosts fail closed.
Certificates and config must be protected regular files. Changing certificate
contents requires a reviewed service restart; Daemon does not restart services.

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

## Independent review follow-up (PR #28)

- **F1:** one active lease per node, two globally. Renewal requires new durable
  upload bytes; maximum lifetime is 24 hours. An expired/old lease without a
  progress record cannot renew. Start a new snapshot identity when exhausted.
- **F2/F3:** only checksum-verified, durably completed objects count toward monthly
  accepted-transfer budgets. Failed/partial writes do not consume that budget;
  partially failed writes truncate back to the last acknowledged offset. This is
  **not** a wire-bandwidth meter. Without an explicit node cap, a configured
  server cap gives each node at most half. Partial data has a fixed 64 MiB/node
  quota and total indexed-plus-partial data a 1 TiB/node ceiling. Configurable
  storage quotas and audited budget overrides remain future work. Begin and GC
  sweep expired/finished partials; automatic periodic maintenance is not wired.
- **F4:** digest verification happens at object completion. Control operations
  compare an indexed verification stamp (device, inode, length, modification and
  change timestamps) rather than hashing payloads. Metadata mismatch fails closed.
  Old unstamped objects require re-verification through upload. Independent
  background scrubbing and fully asynchronous metadata/index work remain pending.
- **F5:** server receive time orders snapshots. Unverified newer snapshots do not
  satisfy `keep_snapshots`; until enough newer restore-tested copies exist,
  older snapshots remain protected. Restoring/marking through a qualified
  runner is still required before retention can safely free those copies.
- **F6:** separate bounded handshakes (32 global, four per source, three-second
  timeout) precede the eight approved-certificate connection slots. A fingerprint
  needs a non-revoked enrolled node or a live unused enrollment approval before
  taking a slot; a CA signature alone is insufficient. Each fingerprint may hold
  two sessions. Headers have a 12-second absolute deadline; reads/writes have a
  12-second inactivity deadline, including keep-alive and incomplete bodies. A
  120-second total connection deadline remains. Guards release on disconnect,
  timeout and cancellation. Existing requests still recheck node authorization.
  Nodes sharing an IP can share the three-second handshake lockout; many approved
  identities can still fill the global cap. Accept errors back off rather than
  terminate the listener. Distributed connection/CPU flooding
  still requires network admission controls; this is not DDoS protection.
- **F7/F8:** dedicated service identity, empty startup environment and descriptor
  closure replace same-user supervision. Explicit action routes and password-bound
  confirmations replace web administration passthrough. The template and source
  are not evidence of a qualified live systemd installation.
- **F9/F10:** agents reject server requests for ciphertext outside their manifest.
  Repeated receipts check indexed metadata and expose the original `verified_at`;
  this is upload-time verification, not a fresh cryptographic scrub or recovery proof.
- **F11 — known limit:** restore leases/attestation remain internal library APIs,
  not supported remote/control actions. The fixed one-hour restore lease has no
  renewal. Do not run long restores concurrently with deletion. No recovery path
  was changed in this repair; dedicated restore authorization/renewal is separate.
- **F12 — partly fixed:** post-commit catalog-file cleanup no longer reports a
  successful logical deletion as failed. Orphan object reconciliation, durable
  cleanup retries and pruning completed/expired lease rows remain unfinished;
  do not claim crash/power-loss qualification. Keep the repository index backed up.
- **F13/F14:** repeated same-second observations preserve hysteresis. New nodes
  cannot use reserved admin names; node audit labels are namespaced. Local control
  records peer UID; dashboard audit records authenticated email and request digest.
  Worker and dashboard events require correlation; there is no global signed audit ledger.
- **F15 — known limit:** no automated certificate rotation, CRL or file-content
  watcher. Node revocation is enforced on signed operations; rotate certificates
  with explicit service restart and independently verify the new identity.

The backup format, age encryption and recovery implementation are unchanged.


## Durable outbound scheduler (source implementation)

Daemon starts an optional Rust scheduler even when its dashboard is disabled.
A private `<controller>/backup-agent.json` enables it. The JSON matches the
`Schedule` type in `src/backup_service/scheduler.rs`: id, node, absolute signing_key
(PKCS8 Ed25519), manifest, objects, readiness paths, targets, policy, next_run
(Unix UTC seconds), paused and link_bytes_per_second. Targets use the existing
Agent Target shape. Secrets remain in protected files; queue rows store paths,
manifest metadata and receipts, never private/recovery key bytes.

The producer must atomically publish an immutable v2 encrypted manifest and keep
its ciphertext objects until every target finishes. This scheduler consumes that
prepared snapshot; it does **not** copy a running database or implement missing
application quiescence adapters. Readiness is a private local adapter report
`{"state":"ready|busy|unsafe|unknown","observed_at":<Unix seconds>}` renewed
within 90 seconds. Unknown/unsafe/stale reports fail closed. Busy sources defer
until the policy threshold, then transfer at the configured ceiling. The hard
ceiling is link_bytes_per_second multiplied by bandwidth_percent/100 for all
scheduled transfers; it is an operator-provided budget, not a measured link rate.

SQLite FULL/WAL and an exclusive worker lock persist due times, frozen inputs,
each target's attempts/backoff, receipts and completion independently. Restart
requeues interrupted work. Successful targets are not resent. At most one target
runs locally at a time. Retry delays grow from one minute to one hour; ten failed
attempts block that target for review. The history limit is 1024 jobs; exceeding
it stops new jobs rather than silently deleting history. Pause/removal or loss of
readiness cancels an active transfer at the next one-second check. A prepared-file
failure does not discard queued work. Configuration changes affect new jobs;
existing target/key-path/manifest choices stay frozen. Changing schedule identity
while jobs remain requires review. Status is persisted in the controller's
`backup-agent-status` document, including blocked/deferred/paused states.

The existing server's acknowledged partial offset resumes interrupted transfers;
repeating finish returns the original verified receipt. Lease admission, maximum
age and progress-renewal limits remain enforced. An exhausted lease may require
an explicitly prepared new snapshot identity; the scheduler does not evade those
limits. No unattended recovery, point-in-time database safety, power-loss or
production service qualification is claimed by these synthetic queue/TLS tests.

Approval waits for the repository lock are bounded to three seconds. The network
inactivity timer is suspended only after the complete request body is extracted
and while server-side handling is active; it resets before writing the response.
The 120-second total cap remains. A busy repository may refuse new sessions;
clients retry idempotently rather than holding handshake capacity indefinitely.
