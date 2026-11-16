# CLI authorization boundaries

Logical accounts use `kagnode user request` with the authenticated envelope on
private stdin. That command connects to the daemon before opening any store or
changing UID. Passwords/tokens never go in arguments. See ROLES-API.md for login,
analytics, confirmations and request formats. The socket rejects the former bare
unauthenticated request format.

The older `status`, `monitor`, `retention`, `settings`, `ha` and `backup-server`
commands are explicitly **host-owner compatibility interfaces**. They require an
existing private installation owned by the caller, or root. Their help says this;
they are not role-aware user tools. Monitoring now reads durable local history
through the existing host-owner dispatcher instead of sending a request format
the daemon rejects. Retention writes preserve expected revision/trim confirmation
and identify the audit actor as `host-owner-cli`, not a claimed logical account.
These commands cannot create an empty replacement installation when a path is wrong.

Root can enter the runtime UID before database access to preserve ownership of
SQLite journal files. Separate logical users must never receive that UID or state
files. Service/broker, backup, setup and install commands retain their existing
root/host-owner checks; they are not exposed through the new roles protocol.
This does not fix Claude's TUI direct-store paths: Claude owns that integration.
No new native permissions, group admission, services or deployments are installed.
