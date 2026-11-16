# Separate-UID local admission — design only

No installation, chmod, account/group creation or production admission change is
authorized by this document. No feature flag enables cross-UID admission here.
The runtime socket remains mode0600; other OS users cannot currently connect.
Root and the Daemon service-account UID remain outside logical-role isolation.

## Objective and identities

A Manager/Viewer runs the terminal as their own Unix user. The daemon runs as a
dedicated non-login service account; that account owns controller state. A separate
unprivileged terminal process must neither open Store nor become the service UID.
A logical session binds the actual Unix peer UID plus logical user ID and current
authorization revision. Membership in the socket-admission group grants permission
to attempt authentication only, not an Operator role or any database privileges.
The root broker remains a separate privileged boundary; socket admission alone
cannot authorize its native operations or supply a free actor string.

## Directory and socket policy

Keep `/srv/kagnode/.../controller` and daemon.sqlite (including journals/WAL),
service keys and backup-worker configuration service-owned0700/0600. Do not add
logical users to the service account's primary group or expose controller state
with directory traversal solely to reach a nested socket.

Use a separately provisioned runtime directory outside controller state, e.g.
`/run/kagnode-control`, service-owned0750 with a dedicated `kagnode-terminal`
admission group. Place `control.sock` there as service-owned0660, same group.
The root-owned parent `/run` and reviewed tmpfiles/systemd RuntimeDirectory policy
must prevent another user replacing the directory/socket. No writable directory
for the admission group; group has traverse/read runtime directory and connect
only. Alternatively root-managed per-user socket ACLs may be used with the same
non-writable directory constraint. ACLs require real filesystem/runtime support;
do not silently fall back to world permissions when unavailable.

A reviewed `--control-socket` setting must accept only absolute root/service-owned
runtime paths, reject symlinks and unsafe ancestors, and protect against removing
an active socket or stale unexpected file. Existing default private path remains
compatible. Client validates peer credentials as the configured daemon service UID
(or root when explicitly deployed that way), with fixed deployment metadata.
The server uses actual SO_PEERCRED, never a UID in JSON. Both ends validate framing,
message bounds/timeouts. Validate directory/socket ownership before connecting
and do not trust an attacker-supplied socket path as a privileged daemon.

## Installer changes required, not implemented

- Reviewed plan identifies service account, distinct admission group, socket path,
  effective modes/ACLs and allowed OS members. Show group membership means login
  admission, not logical privilege. Never add all interactive users automatically.
- Root installer creates a non-login service user and separate admission group
  idempotently; preserve existing owners/IDs and refuse conflicting reused names.
  Existing installations require a migration plan with rollback before chown.
- Provision RuntimeDirectory and socket group/mode with explicit ordering. Service
  restart is a reviewed operation; do not rewrite a running installation merely
  by installing source. Prevent environment/config injection into group/path args.
- No supplementary group may grant daemon state, keys or broker write privileges.
  Root-only policy controls admission changes; removal needs session invalidation
  tied to peer UID plus connection admission refresh, not a Unix login restart
  assumption. Account disable independently invalidates logical sessions.
- Record planned/applied ownership/membership/actions and receipts without secrets.
  Rollback reverses only entries created by this installation, not unrelated groups
  or users. Keep service/database paths and upgrade compatibility. On uninstall,
  retain user data and do not remove a user/group shared by another service.
- Client launch must NOT use setuid/setgid/sudo-to-service-user. Any current root
  compatibility UID drop must not silently change a different user's peer identity.
  TUI/CLI clients use only authenticated socket methods; role presentation is not
  authorization. Claude owns the UI/client integration; no screen changes here.

## Owner mode and recovery

Passwordless mode remains tied to the original recorded machine-owner UID. An
admitted different UID cannot obtain owner_session. Expanding admission cannot
change owner_uid or create a new implicit Operator. Protected stores require
password login. Root recovery accepts only true root peer credentials over the
reviewed local interface; an Operator role from a non-root UID cannot invoke it.
No remote reset endpoint, token-in-URL or broker password override is introduced.

## Qualification and enablement gate

In a disposable VM/container with real distinct numeric UIDs/groups, test:

1. Manager/Viewer can connect and login; cannot stat/open controller databases,
   WAL/journal, keys, backup worker state, service config or broker credentials.
   No inherited fd or environment exposes those files.
2. Nonmember, removed member, wrong-owner socket, symlink/stale-file replacement
   and malicious competing listener are refused. Client rejects a fake daemon
   peer rather than sending a password/token to it.
3. Session from UID A fails from UID B; membership alone never supplies logical
   role. Disabled/revised account fails immediately; concurrent sessions respect
   current grants. Existing owner-only transport remains unchanged by default.
4. Owner mode and root recovery behave as above. A non-root Operator cannot reset
   through root recovery. Root/service-account bypass limits are documented.
5. Socket activation/restart/reboot, runtime directory cleanup, busy listener,
   dropped group access, filesystem ACL lack and interrupted installer migration
   fail safely; rollback restores old access without changing user data.
6. Direct-store CLI/TUI actions cannot bypass the authenticated path from an
   admitted lower-role UID; actor-bound root broker and disposable native control
   qualification must precede enabling those controls in capabilities.

Independent review of installer and runtime changes plus these executed tests is
required before any cross-UID flag can be enabled. This design is not evidence of
implemented admission, working remote agents, HA or production native security.
