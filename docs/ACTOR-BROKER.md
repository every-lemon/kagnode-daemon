# Actor-bound root authorization substrate

Draft backend source only. No release, installation, production native eligibility
or native service qualification follows from these tests. All health/log/boot/Core/
backup adapters and advertised native controls remain unavailable. `serve_root` is
an uninstalled library entry point with an always-unavailable production dispatcher;
there is no new CLI service or installer activation. Root-owned socket mode0600
also deliberately leaves separate-service-UID transport provisioning unqualified.
The existing legacy broker now refuses every nonroot peer, including its previously
registered service UID; new host-root outcomes explicitly record `host-root`.
Root/service account remain trusted and outside logical-user isolation.

The local role protocol accepts `broker_intent` with `request` containing exactly
`request_id`, fixed canonical `product`, typed `action`, and lower-case64hex
`plan_sha256`. The nested request ID must equal the envelope request ID. Actions:
`health`, `logs`, `core_plan`, `core_apply`, `core_rollback`, `backup_manage`, plus
`{"boot_set":{"enabled":true}}` and `{"backup_pin":{"pinned":true}}`.
These are typed intent descriptions, never commands, unit names or paths. The
placeholder backup management intent cannot perform any backup action; later
adapter work must define exact typed parameters and preserve existing policy,
revision, certificate, deletion confirmation and encryption/recovery contracts.

Operator or exact Manager product grants authorize health(view), logs(operate),
Core plan(manage), boot/Core apply/rollback/backup management(manage), backup pin
(operate). Viewer and unknown/ungranted products refuse. Backup intents accept
only `backup`. Reads need current scoped session, with no password poll. Mutations
need existing protected-mode exact one-use password confirmation, which includes
the nested request ID, action, product and plan. Confirmation is consumed before
attempt even if later validation fails. No free actor/UID fields are accepted.
Browser native intents are refused; no web route or UI was changed.

Controller issuance transaction resolves actor from current session and persists
intent binding installation identity, logical actor, kernel-origin UID, action/
product/plan/request, auth revision, security revision, protection mode and30second
expiry. Durable identity is SHA256(installation, actor, request ID); another actor
can reuse the same chosen request ID without taking another user's slot. The
nonce hash and session hash stay private in controller SQLite. Raw nonce exists
only in a bounded128-entry expiring process map and private root wire; it never
enters a user-facing Value, receipt or audit. Process loss loses dispatch authority;
persisted intent remains inspection-only. No new signing key is introduced.

Runtime finishes the role transaction and drops Store mutex before private root
socket I/O. A separate private `run/authority.sock` listener accepts only actual
kernel UID0;4callback slots,16KiB frames and2second input/output deadlines cannot
be occupied by ordinary controller dispatch workers. Root checks actual service
peer credentials and connects to this pinned private callback, checking the real
service UID. It never opens service SQLite or WAL. Callback transaction checks
exact stored binding/nonce/expiry, current session UID/lifetime, actor/auth revision,
security revision and current role/product grant, and consumes once. Mutations
also recheck fresh password authentication. This transaction is the authorization
linearization point; later revocation cannot undo an already admitted operation.

Root journal is separate protected root SQLite with synchronous FULL. It commits
pending before callback and admitted before dispatch. Pending/admitted on restart
become uncertain. Exact same scoped binding returns old state without execution;
changed nonce/actor/product/plan under that identity refuses. Callback uncertainty,
dispatch failure or lost/mismatched receipt is uncertain, never blind-retry
permission. No callback or dispatcher acquires controller Store across root I/O.
An unavailable adapter records unavailable, never fake success. Synthetic injected
functions are private to unit tests and cannot be selected over the wire.

`broker_receipt` has `request_id` and `product`, requires current session and product
view grant and always the same logical actor, including for Operators. It returns
controller binding/state and optional root receipt. A root operation completed
before controller receipt persistence can leave only consumed/uncertain controller
state: inspect root journal under host-root authority, do not generate a replacement
nonce or automatically redispatch. There is deliberately no automatic reconciliation
or uncertain-resolution endpoint in this draft. Audit records resolved actor/UID/
request/outcome; durable bindings carry the exact reviewed plan. No secrets/log
output is persisted in these receipts.

Remaining gates: independent security review, actual service-UID private transport
provisioning, actual service-manager callback lifecycle qualification, fixed adapter implementation
and disposable native qualification, owner/TUI integration, root journal inspection
UX and reviewed resolution, resource/retention policy. No live service command,
Core bundle, backup format or production state was changed.

Current activation guard is unconditional in production: `broker_intent` and its
reauthentication target return `control_unavailable` before password work,
confirmation consumption or intent creation. Only private unit-test Store state
can exercise synthetic issuance/dispatch. Capabilities remain unchanged/false.
Controller intent history admits at most4 unresolved per actor,256 total per actor,
and4096 total; the transient map also limits4 per actor/128 globally. Full histories
cause admission backpressure; uncertain/security records are never discarded.

Callback startup synchronously binds before the public runtime can listen. A stale
socket is removed only after protected ownership/mode/type checks, refused bounded
connection and unchanged inode/device recheck; a live or ambiguous endpoint refuses
startup. The runtime supervises callback task failure. Both listeners tolerate
accept/peer-credential errors. Private controller connect uses nonblocking Unix
connect with a deadline, including unavailable/full-backlog refusal. Root journal
holds an exclusive instance flock before performing startup uncertain recovery;
a second broker cannot rewrite an active process's pending operations.
