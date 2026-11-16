# Lossless audit retention — proposed design, not an enabled feature

## Current limitation

The `audit` table grows without bound. The administrator list already returns at
most100 rows; that bounds responses, not storage. Logical user requests can create
refusal events. Do not delete them to satisfy disk limits or claim that pagination
implements retention. Root/service-account owners remain outside the audit trust
boundary; this is not a tamper-proof ledger. There is no automatic pruning in this
branch. I2 remains an implementation and qualification blocker.

## Required policy and invariants

A bounded total byte budget and lossless retention for an infinite stream require
external capacity or refusal of new work. A finite local ring that discards older
security events does not meet the requirement. Keep all user/login/role/grant/
confirmation/recovery/native-operation outcomes, including denied attempts and
uncertain outcomes. No passwords, session tokens, confirmation secrets or arbitrary
untrusted request bodies in event details.

Proposed reviewed policy: hot-store row/byte and age thresholds; immutable archive
segment size/count; local archive byte quota; external verified-copy state; minimum
local recent-history retention; failure mode. Values must be selected against the
installed disk, with the standing20GiB reserve and estimated next segment space.
No production defaults or timers are enabled by this design. Only Operators may
change policy, using fresh payload-bound confirmation and expected revision; the
policy change is itself an event and receipt. Viewer receives no audit data.

## Archive protocol

1. Allocate a durable archive-job intent in SQLite with a fixed inclusive event-ID
   range, row count and previous committed segment digest. Retain the source rows.
   New events get monotonically increasing IDs and cannot enter the frozen range.
2. Export canonical typed events to a new private temporary segment using fixed
   paths and secure ownership/modes; reject symlink/hardlink paths. Stream export
   rather than holding all events or the database mutex in memory. Include schema,
   source installation identity, min/max IDs/timestamps, count, payload digest and
   previous-segment digest. Avoid exposing archive paths to non-Operators.
3. Flush segment, atomically rename and fsync its directory. Reopen and verify
   content digest, event count/ID range and schema. Record verified local segment
   receipt in SQLite. An exported file without a receipt is adoptable only after
   validating the durable intent; arbitrary files must never authorize pruning.
4. Copy to the independently configured private archival target. Preserve the
   existing backup encryption/key rules; never put recovery keys in the segment
   or repo. Hash local plaintext only in private memory; public references contain
   encrypted-asset hashes. Require actual downloaded-copy decryption/inventory
   verification before treating off-host archival as durable. Mere upload/mail/
   HTTP acceptance is not verified preservation.
5. In one SQLite transaction, recheck the exact retained range against the frozen
   digest and receipt, then delete only rows covered by a verified archive according
   to the approved policy. Record a compact immutable range/receipt anchor and a
   retention event outside the removed range. Do not delete active operation
   receipts, account revision history or confirmation state as collateral cleanup.
6. Delete old local segments only when the private verified external-copy receipt
   and minimum local-retention requirements hold. Keep an ordered index enabling
   archive retrieval by ID/time. Hot-store gaps must be visibly marked archived,
   not presented as nonexistent events. Restore/rescan validates the entire chain;
   a digest chain detects accidental modification, not malicious root forgery.

## Failure and capacity behavior

Crash or disk-full before step5 retains source rows. Crash after rename may leave
an orphan segment; reconcile only against its frozen job. Crash after SQLite
pruning leaves the already-fsynced verified segment and durable receipt. Retry is
idempotent by job/range/digest, not a second export with a new invented range.
Never remove rows merely because a segment filename exists. Never prune on an
unverified external response or a failed fsync.

At archive quota/high-water, block new mutating/admin work before executing it if
its audit reservation cannot be durably recorded; do not perform side effects and
then pretend the audit succeeded. Authentication refusals need an independently
reserved bounded failure journal and explicit capacity-denied aggregation design:
aggregation must preserve counts, interval and cause, cannot claim individual
events it did not retain, and needs independent review before enabling. A full
failure journal must fail closed and surface degraded admission to the local
owner. Existing sessions' analytics may remain available if read-audit policy
explicitly allows it. Root recovery must reserve its event before resetting any
credentials. Do not silently bypass logging for an emergency reset.

## Qualification before implementation ships

Test each crash boundary, short write/rename/fsync/SQLite failure, restart/retry,
concurrent writers, duplicate intents/receipts, stale policy/revision, malformed
archives, source range changed, archive target outage, full quota and local reserve.
Verify exact before/after event-ID and content multiset through export/prune/
restart/download/restore using synthetic events. Test Operator authorization and
confirmation replay; test Viewer/Manager inability to read/change/export archives.
Bound segment memory, execution time and mutex duration. Test current-schema
migration and rollback with no removed rows until an independent review approves
archive/prune semantics. No scheduler or live archival target is provisioned here.
