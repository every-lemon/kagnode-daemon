# Separate-UID admission backend draft

Source only, based on main 7efe077. This independent draft does not modify or
integrate installer draft63, actor broker65, legacy64 or pipeline60. No release,
installation, group creation, permission change or production listener is enabled.
`local_admission::QUALIFIED` is false with no runtime override. Both `request` and
`serve` refuse before endpoint access. There is no dashboard setting or CLI flag to enable admission.

The normal compiled transport implements protocol1 using real SO_PEERCRED and
the existing roles dispatcher. Production entry is unreachable behind the false
gate; tests inject only fixture paths and policy/membership into the same private
compiled listener and dispatcher. The server admits at most eight concurrent
connections and two per real UID before login, while existing password workers
remain bounded to two. Absolute three-second input/output frame deadlines prevent
byte trickling from extending a slot indefinitely; response input on the client
also has an absolute whole-exchange deadline. Password computation uses the
existing bounded roles scheduler; accepted mutations cannot be undone by a client
timeout.

The guarded listener validates root ancestors and service-owned0750 directory,
binds a socket inside a newly created0700 staging directory, assigns the distinct
GID/0660, then atomically publishes a hard link without overwriting any existing
path. The private staging link is removed; any stale/live/fake public path is
retained and refused. Unsupported filesystem hard links fail closed. The server
does not automatically remove a socket after exit; reviewed restart/rollback
must verify and remove its own stale inode. Production request code verifies
policy, directory/socket and real server UID before serializing credentials.
Nonblocking connect refuses full backlogs immediately. There is no attacker
endpoint fallback. No production listener was started by these tests.

## Callable client contract

`runtime::authenticated_request(root: &Path, request: &roles::Envelope) ->
anyhow::Result<serde_json::Value>` remains the CLI entry point. It delegates to
`local_admission::private_request`, validates private owner directory0700,
run0700, socket0600 and real server UID before sending anything. It does not open
Store or change UID. Existing host-owner direct-Store commands remain host-owner
only; this does not qualify the root TUI demotion/direct-Store path.

`local_admission::request(&roles::Envelope) -> Result<Value>` is the exact future
Claude TUI backend entry point for separate UIDs. It takes no root/socket path,
UID, role or endpoint argument. It currently always refuses. Claude must not
catch the refusal and fall back to direct Store or sudo/setuid/service-UID launch.
No `src/tui*.rs`, web or Core source is changed here.

The fixed locator is `/etc/kagnode/local-admission.json`: root-owned single-link
regular0644 in root-owned nonwritable ancestors, opened O_NOFOLLOW/nonblocking
with a16KiB bound. Public metadata contains no credentials. Fields are enabled
(default staging value false), positive revision, daemon_uid, service_gid,
admission_gid, admission_group=`kagnode-terminal`, explicit numeric members.
Unknown fields are refused: a path in JSON cannot redirect the client. The
admission GID must differ from root and the service primary GID. Members exclude
root, service UID and the browser transport sentinel.

Future socket is fixed `/run/kagnode-control/control.sock`, outside private
controller state. `/run` ancestors are root-owned/nonwritable, directory is
service-owned0750 with the distinct admission GID and socket service-owned0660
with that GID. Clients verify this and kernel peer UID before serialization.
Controller DB/WAL/journal, keys and configuration stay0700/0600; clients never
receive membership of the service primary group.

## Membership and authorization

The root policy is reread for each request. Production membership helper rereads
local `/etc/passwd` and `/etc/group`, rather than trusting a client's stale kernel
supplementary groups. This is a local-files account model; NSS/directory-service
membership support is not implemented or claimed. The admitted UID must appear
in both root policy and current admission group, and must not belong to the
service primary group. Root/service UID are deployment trust identities, not
logical member privileges. Fixture transport refreshes before input, immediately
before dispatch and before reply, so removal refuses existing connections.

Membership only permits authentication attempts. Actual peer UID is passed to
existing role/session checks, which reject a UID-A token used by UID-B and retain
Viewer analytics, Manager explicit grants, owner UID and root recovery boundaries.
No asserted UID, central profile, group membership or service UID alias creates an
Operator. Existing per-role checks and password throttles are unchanged. A policy
revision does not itself grant privilege. Removal in the middle of an already
executing request cannot undo its accepted mutation; full concurrent native
revocation qualification remains required before enablement.

## Installer integration and ordering

`installer_plan(&Policy) -> Result<Value>` renders the exact fixed paths, IDs,
modes, policy and reviewed ordering; it accepts disabled policies only.
`apply_installer_plan(&Value) -> Result<()>` always refuses. No installer is
silently changed to invoke it, and no group/user/files are provisioned here.
A future reviewed installer must reject existing name/ID conflicts, explicitly
review each member, provision the root policy parent then disabled metadata,
then service-owned runtime directory with the distinct GID, bind privately,
set GID/0660 before atomic publication. Never unlink a stale/live/unexpected path.
The plan renders an exact numeric tmpfiles directory rule plus UMask0077,
SupplementaryGroups=kagnode-terminal and ordering after tmpfiles setup. It omits
RuntimeDirectory because its default service-primary-group ownership would
violate the distinct group boundary. No standalone unit fragment may be applied.

Draft63 Owner!=0 remains unavailable until an owner-only transport is independently
qualified. Separate-UID membership does not satisfy that installer gate. Rollback
must retain controller files and only reverse resources created by the reviewed
installation. Restart/reboot/membership removal must be qualified in disposable
native systems; the previous failed SSH VM boot is not a pass and is not retried.

## Evidence limits

Unit fixtures test validation, disabled gates, permission plans, metadata
symlink/FIFO/mode rejection, live/stale socket refusal, actual kernel peer UID,
framed dispatch, refresh removal, absolute trickle deadlines, UID fairness and
cross-UID session rejection. An existing nobody65534 client actually connects to
the same staged/published socket and is refused a non-owner owner_session; the
server observes actual kernel UID65534. Its membership policy remains synthetic. Root-only
filesystem fixtures skip without root and are explicitly synthetic. All-root
socket pairs do not qualify separate Unix clients. Existing roles suites cover
permission matrices, escalation, owner mode and root recovery separately.
Independent Claude review plus real distinct UID/group, restart/removal, state
inaccessibility, competing listener and rollback qualification are mandatory
before any production admission enablement. No native VM qualification is claimed.
