# Daemon roles and authenticated local control — security specification

Status: specification for independent review, not security qualification, release or deployment. Rust backend belongs to Codex; all terminal/web/Core UI belongs to Claude. Base is backup PR28 at0991e7d; no changes to PR30/33. Native operations in phase4 remain blocked until phases1–3 are reviewed. No UI files may be edited to shortcut integration.

## Assumptions (owner defaults, explicit)

- Assumption A1: several Operators are allowed; first configured user is an Operator. Operators manage all Daemon users/settings/products.
- Assumption A2: Managers have independent per-product grants ordered view < operate < manage. Missing grant denies. No wildcard, implicit grant through email, or central-account privilege promotion.
- Assumption A3: Viewers receive server analytics only: no logs, inventory secrets, audit feed, backups, actions or management settings. Analytics responses omit sensitive configuration and raw user/session data.
- Assumption A4: lost-password recovery is a root-only local reset command with a durable audit entry and global session/re-auth invalidation for the target. No email-only reset or remote recovery endpoint.
- Assumption A5: logical users may share a machine login, but socket credentials remain bound to the caller's Unix uid. Root and the Daemon's service-account owner are outside the isolation boundary.
- Assumption A6: passwordless mode is single-owner only: one implicit Operator tied to the machine owner's recorded uid, no remote access, no additional users until password protection is enabled. Root recovery remains possible. Password protection is offered during setup by Claude UI; backend accepts explicit protected/owner mode, never silently downgrades.

## Threat model and non-goals

Defend against an authenticated Viewer/Manager exceeding grants, forged actors, stolen/replayed confirmations, stale roles/sessions, cross-uid token reuse and accidental self-lockout. Deny unknown actions/products/levels and fail closed on storage failures. Unix peer credentials authorize transport admission, not logical privileges. Every action resolves its principal inside the server; client actor/role claims are rejected.

Roles do NOT protect against root or the Daemon service account: either can read/change private state, replace binaries, inspect process memory or bypass the socket via owned database files. A read-only Viewer dashboard cannot claim confidentiality against those identities. Socket mode/group provisioning is separate from logical login: mode0600 initially preserves existing access, reviewed group installation may widen admission later; never chmod state/database world-readable to support multiple accounts. No role feature enables networking, service restarts, shell execution or HA.

## Data model and migration

Use transactional additive migrations in existing daemon.sqlite, preserving installed paths, settings, documents, admin hashes, vaults and backup format.

- users: stable id, normalized unique email, password_hash(nullable only for implicit owner), role(operator/manager/viewer), disabled, created_at, created_by, auth_revision. created_by is immutable server-assigned principal (migration/root-recovery special actor explicit).
- user_grants: user_id + allowlisted product_id unique, level(view/operate/manage). Only Managers may have grants; changing role atomically reconciles grants. Operator rights derive from role; Viewer grants cannot elevate them.
- security configuration: protection mode protected/owner; recorded owner_uid and implicit owner id; admin_enabled=false by default (separate from web_enabled/dashboard). Persist revision for compare-and-swap updates.
- terminal_sessions: random token hash only, user_id, peer_uid, auth_revision, created/expires/last-use, authenticated_at. No plaintext token/password in audit, receipts, process arguments or disk.
- step_up: random one-use token hash, session hash, auth_revision, exact action/product/request digest, expiry. Transactional compare/delete when consuming.
- rate limits: persistent failed-login windows per peer uid and normalized identity, plus bounded process/global concurrency; no unlimited identity keys. Generic refusal messages avoid account enumeration.

Migration maps every existing admins row to Operator without rehashing/resetting password; repeat open is idempotent. Existing admin sessions must be invalidated or checked against new user revision on every use. Protected legacy stores remain protected. Existing password verification handlers cannot continue treating any users row as a full admin. Last enabled Operator cannot be disabled, demoted or deleted: enforce transactionally even concurrent requests. Only root recovery may repair a corrupted/no-operator state and must audit it.

## Permission matrix (server enforced)

| Action class | Operator | Manager | Viewer |
| --- | --- | --- | --- |
| overview/metrics/analytics retention read | yes | yes, analytics only | yes, analytics only |
| raw audit/security settings/user list and mutations/admin_enabled | yes | deny | deny |
| per-product health/details | yes | product:view or higher, sanitized | analytics only; no product details |
| logs (read-only bounded, sanitized) | yes | product:operate or higher | deny |
| boot enable/disable | yes +step-up | product:manage +step-up | deny |
| Core status/plan | yes | product:view (status), manage (plan) | deny |
| Core apply/rollback/policy | yes +step-up | product:manage +step-up | deny |
| backup server/agent/node/snapshot/policy data | yes | explicit backup product:view or higher | deny |
| backup pin | yes | backup:operate or higher | deny |
| backup approve/revoke/rotate/delete/unpin/GC/policy | yes +step-up | backup:manage +step-up | deny |
| global retention/profile/install/uninstall/HA/native broker plan/apply | yes +step-up where risky | deny unless future explicitly mapped fixed product action | deny |
| own whoami/logout/password-change | yes | yes | yes |

Backup grant uses a fixed catalog identity documented in code; do not accept arbitrary filesystem/service names as products. No action is enabled merely because it appears in capabilities. Existing broker reviewed hashes, native admission gate and safety checks still apply after role check. Anything not listed is denied for non-Operators. User creation/role/grant/disable/password reset requires Operator re-auth; creating elevated identities never inherits requester-supplied created_by.

## Local socket/API contract (version1)

Line-delimited bounded JSON over existing private control socket: request protocol version, request_id, action, session token (absent only for login/owner bootstrap), typed payload; unknown fields rejected. Max16KiB header/request, bounded reply/body, read/write deadlines, bounded connections and password-hash workers. Clients can reconnect per request; the server checks peer uid every time.

- login(account,password) -> token, expiry, whoami/capabilities; password parsed in memory and zeroized as soon as feasible. Never put secrets in argv. Existing session token cannot be supplied as an actor assertion.
- owner_session -> session only if owner mode AND peer uid equals recorded machine owner. Response explicitly includes protection=unprotected, implicit_operator=true. Protected mode denies it. No web/browser use of owner_session.
- whoami -> stable id, account, role, protection mode, authorized capabilities and auth_revision (no hashes).
- capabilities -> filtered fixed identifiers and product scopes, calculated from current DB state, not cached trusted client-side.
- reauthenticate(password, intended action, exact payload) -> single-use short-lived confirmation. Applying action uses same canonical typed payload digest and original reviewed plan hash. Bind to uid/session/product/actor/revision, consume atomically, reject replay even on uncertain results; operator inspects outcome before retry.
- user.list/create/update/disable/reset_password and security.admin_enabled get/set: Operator only; changes use expected revision and risky confirmation. Self password-change requires current password and invalidates all old sessions; fresh login required.
- logout deletes session and confirmations. Disabled/demoted/password-changed users lose active authorization immediately (revision check) across restarts. Reauth never resurrects a disabled session.

Assumed session limits:15-minute idle,8-hour absolute, confirmation90seconds and fresh-password requirement5minutes; login failure limit5 per identity+uid per15minutes, independent uid/global bounds. Apply limits to correct-password failures too; use dummy password verification for absent/disabled users where practical. Counters survive restart; do not log passwords. Exact wire identifiers and response envelope must be published in docs with implementation; this spec alone is not a promise they already exist.

## Audit and receipts

Every accepted mutation records stable user id/account, peer uid, mode, action/product, request_id, reviewed-plan digest and outcome; rejected authorization/login/recovery attempts use sanitized requested identity. No caller-provided free actor. For pre-existing audit rows retain historical actor without inventing attribution. Read security-sensitive access is auditable, with bounded retention work documented separately. Broker receipt includes server-resolved actor and plan hash; signature/hash binds that actor so receipts cannot be swapped between users. Crash after native mutation remains uncertain, never invented success. Protect audit from logical users, not root; no tamper-proof claim.

## Setup, admin and recovery behavior

Protected mode supports account+password socket login; user creation selects role and Managers' grants. Owner mode creates exactly one implicit Operator, blocks remote/web administration and additional-user creation until protection is added. Add-password operation requires owner uid/current authority and transitions atomically to protected mode; invalidate owner sessions. Recovery reset accepts password through private input/file with ownership/mode checks, never argv; require euid0 and append root-recovery audit, invalidate affected sessions, preserve other operators. Root reset does not silently enable web admin.

admin_enabled is separate and defaults false on both fresh setup and migrated stores. Only Operator may change it with step-up. Turning it off prevents admin APIs/federation access even if dashboard remains enabled. Role enforcement must cover legacy web/broker entry points, not just new socket; until integration is complete those endpoints must remain unavailable to newly introduced lower roles. Claude builds protected terminal login/unprotected banner and web admin presentation; do not edit those files here. Dashboard auth migration/integration is a release blocker if a lower role can reach a legacy full-admin path.

## Validation/review gates

Before security-ready: migration and repeat migration, all roles×actions and grant levels, denied unknown inputs, no implicit escalation, changed-role invalidation, forged actor/session, uid binding, expiration/replay/restart, rate limits, concurrent last-Operator changes, owner mode/add-password/root recovery, admin gate separate from dashboard, broker receipt identity, legacy web/broker bypass checks. Disposable synthetic fixtures only. Rustfmt, Clippy-Dwarnings, cargo test--workspace, inventory and protected CI. Claude independently reviews both spec and implementation. Existing UI cannot be called secure with roles until its client integration removes direct store access and passes end-to-end tests. Product native controls phase4 remain deferred until this gate is reviewed and disposable native qualification exists.
