# Authenticated local control, protocol 1

Development source, pending independent review and Claude's client integration.
No native product controls are enabled by this work. The legacy unauthenticated
terminal protocol is rejected; the old TUI has not been converted or qualified.
Do not ship this branch as an integrated multi-user dashboard yet.

## Installation and trust boundary

`kagnode init --email ... --password-file /private/file` creates an Operator in
protected mode. Existing installations migrate every legacy administrator to an
Operator without rehashing their passwords; existing web sessions are invalidated
once. Reopening does not reimport removed accounts or reset roles/settings.
`kagnode init-owner` is an explicit alternative for a genuinely empty store. It
records the initializing effective UID, creates one implicit Operator, disables
web administration and dashboard, and cannot replace a protected installation.

`admin_enabled` defaults false, independent of `web_enabled`. The current legacy
web handlers remain Operator-only and also require admin_enabled. New Manager or
Viewer accounts cannot use legacy web login. Role changes/reset invalidate both
terminal and legacy web sessions. Claude must implement lower-role web presentation
and authenticated TUI clients separately. Backend `user()` authorization is the
only web.rs change here; no presentation or Core files were changed.

The current socket remains `<controller>/run/control.sock`, mode0600 inside the
private runtime directory. Root and the service account are outside the security
boundary. Logical users must not receive access to the database or service UID.
The old direct-Store CLI/TUI/native broker are host-owner compatibility interfaces,
not authenticated lower-role entry points. Reviewed socket/group admission for
separate client UIDs is not installed by this branch. Do not widen database modes.
A separately provisioned service UID and end-to-end client/installer qualification
are release prerequisites for actual multi-user isolation.

Root recovery uses the *running* private daemon: the socket checks SO_PEERCRED uid0.
This avoids root-owned SQLite journals and never trusts a caller's root/actor field.
No offline recovery helper, email reset endpoint or browser owner-mode access exists.

## Framing and response

One newline-terminated JSON request per connection, maximum16KiB; unknown fields,
actions, products and levels are refused. Maximum8 connections,2 blocking workers,
3-second input/output deadlines and2MiB reply limit. The kernel peer UID is bound
to every session and never supplied by JSON. The CLI `kagnode user <verb>` reads the
request from bounded stdin; it does not open the database or drop the caller UID.
Passwords and session tokens must never be placed in command arguments. Regular-file
stdin must be caller-owned, single-link and mode0600 (or stricter); pipes/terminal
input are accepted. Malformed CLI requests produce a generic error without echoing
unknown field/variant values.

```json
{"version":1,"request_id":"unique-review-id","session":null,"confirmation":null,"payload":{"action":"login","account":"person@example.invalid","password":"entered privately"}}
```

Success over the socket: `{ "ok":true, "value":{...} }`; refusal:
`{ "ok":false, "error":"safe message" }`. The CLI prints only value on success,
returns nonzero on error. No parser supports caller-supplied actor/role assertions.
Login's returned token is sensitive output intended for client memory, not logs.

Requests below list the `payload`; other envelope fields remain as above.
Use `user request` for any action, or exact matching aliases: `login`,
`owner-session`, `whoami`, `capabilities`, `logout`, `reauthenticate`, `list`,
`create`, `update`, `reset-password`, `change-password`, `enable-protection`,
`security-get`, `security-set`, `root-recover`.

| Action | Fields and behavior |
| --- | --- |
| login | account,password; protected mode only. Returns token,expires_at,whoami. |
| owner_session | no session/confirmation; owner mode and exact recorded peer UID only. Returns protection=unprotected, implicit_operator=true in whoami. |
| whoami | current user id,account,role,disabled,auth_revision,created_at,created_by,grants; protection and capabilities. No credential hashes. |
| capabilities | implemented global actions/product scopes; native_actions_enabled=false. Capability display never replaces request authorization. |
| logout | invalidate this session and confirmations. |
| reauthenticate | password,target: exact typed payload of a risky action. Returns confirmation,expires_in=90. One outstanding confirmation per session. |
| user_list | Operator only, users array, maximum1000. |
| user_create | account,password,role,grants; Operator + confirmation. created_by is server-resolved. |
| user_update | id,expected_revision,role,grants,disabled; Operator + confirmation. Atomically invalidates sessions and reconciles grants. Cannot remove last enabled Operator. |
| user_reset_password | id,expected_revision,password; Operator + confirmation; invalidates all target sessions. |
| change_password | current_password,password; protected mode, own account only, new sign-in required. |
| enable_protection | account,password; owner session+matching owner UID only; atomic transition, revoke owner sessions. |
| security_get | Operator only: mode,owner_uid,admin_enabled,revision. |
| security_set | expected_revision,admin_enabled; Operator + confirmation. Disabling revokes legacy web sessions; does not stop dashboard/managed services. |
| overview | all roles; analytics node/sample/history only, no audit/application inventory/security settings. |
| metrics | name,since,until; all roles; existing bounded metric-query validation applies. |
| retention | all roles; read monitoring revision,policy,presets_days. |
| set_retention | revision,policy,confirm_trim; Operator + confirmation; existing policy limits, revision guard and explicit trim guard retained. |
| product_status | fixed product; Operator or Manager view+. Returns fixed id,name and native_actions_enabled=false, not native health qualification. |
| backup_agent_status | Operator or Manager backup:view+; persisted observation, never a remote probe. |
| audit | Operator only; latest100 security/legacy audit entries. |
| receipt_get | request_id; Operator only; verify keyed actor-bound receipt, return receipt,mac,verified. Integrity mismatch refuses. |
| root_recover | account,password; no session, peer uid0 only. Resets/repairs an Operator, revokes target sessions and audits recovery. Leaves admin_enabled unchanged. Owner mode transitions to protected; old implicit owner disabled if different. |

Roles: `operator`, `manager`, `viewer`. Grant map example:
`{"mail":"view","backup":"manage"}`. Levels are `view < operate < manage`.
Only Managers have grants. Fixed product IDs: proxy-manager,vpn,entropy,media,
passwords,mail,httpboot,netctl plus reserved backup. Aliases, wildcard and paths
are rejected for grants. Role checks use current DB state on every request.
User expected_revision is auth_revision; security expected_revision is security
configuration revision; retention revision is its document revision.

## Confirmation, failure and audit

First construct the exact target payload, call reauthenticate, then send it with
`confirmation` on its own envelope. Tokens bind session/UID/user revision and
canonical typed payload. They expire90seconds after fresh authentication; the
server also requires authentication within5minutes. A valid token is consumed
before attempting the mutation even if revision/validation fails. A token for a
different payload is refused. Never automatically retry a timed-out mutation;
inspect state/receipt, obtain fresh confirmation and review again.

Sessions have15-minute idle and8-hour absolute expiry, survive server restart,
and never store plaintext tokens. Only failed password checks charge persistent
15-minute buckets: 5 login failures per account+UID, a separate higher ceiling
of 20 reauthentication/password-change failures per account+UID, 50 failures per
UID and 200 global. A login lockout also blocks confirmations. A successful
password check clears that account's login and reauthentication buckets, but
never resets UID/global failure totals. Successful administration does not
consume the failure budget. Checks and accounting remain serialized by the
store mutex. Unknown identity keys are bounded by the UID/global ceilings.
Disabled
or absent identities use a dummy Argon2 verification. Root recovery is root-only,
not an unthrottled public password endpoint. Request-password strings are zeroized
on drop; no claim is made that all allocator/serializer copies can be erased.

Accepted security mutations and logout have transactionally stored receipts;
request IDs cannot be reused. A private installation HMAC key binds receipt actor,
peer UID, mode, action, request digest, outcome, time and request ID. Confirmation
payload digests use the same keyed construction so a persisted new-password
request digest is not an unkeyed fast password oracle. Audit records stable actor
ID plus account context, peer UID, mode, action, request ID and outcome; payloads,
passwords and tokens are excluded. Denied requests are audited with safe summaries.
This is not tamper proof against root/service-owner compromise. Key rotation and
bounded audit/receipt history retention need separate review.

## Deferred integration

The permission matrix also defines future logs/Core/backup-management/native
intents, but no socket action invokes those engines yet. They are not advertised
as available. Existing backup cryptographic format/recovery stays unchanged.
No product start/stop, installation, HA or native broker apply was added. Those
require independent phase1–3 review, authenticated actor-bound broker integration,
and disposable service qualification before phase4. Existing direct-owner broker
receipts remain historical; do not mislabel them as these new logical-user receipts.
