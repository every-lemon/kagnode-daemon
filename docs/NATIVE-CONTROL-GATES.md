# Native control review gates

Follow-up 2 adds **availability reporting**, not native control implementation.
Authenticated `product_controls {product}` requires Operator or Manager view+ for
the exact fixed product ID; Viewers and unknown/ungranted products are refused
before metadata is returned. The response has `native_actions_enabled:false` and
per-control `available:false`, machine code `control_unavailable`, required grant
and a specific reason. These entries are not executable capabilities. Unknown
execution payloads remain rejected by the typed protocol; do not convert an
availability response into a successful operation in the UI.

| Control | Minimum intended grant | Work required before enabling |
| --- | --- | --- |
| product_health | view | Scoped health adapter, bounded timeout/output and disposable validation |
| product_logs | operate | Fixed unit allowlist, bounded/redacted records, no arbitrary paths/commands; leak and permission qualification |
| boot_set | manage | Fixed privileged broker action and durable actor-bound plan, confirmation and receipt |
| core_plan/apply/rollback | manage | Verified local Core adapter plus actor-bound privileged request and atomic rollback qualification |
| backup_approve/revoke/rotate_certificate/delete/policy | manage | Extend backup supervisor to validate current logical actor and reviewed payload/confirmation; synthetic failure/replay qualification |
| backup_pin | operate | Same actor-bound backup supervisor integration |

The existing service broker trusts a registered Unix service UID; its request does
not carry a verified logical-user authorization decision or bind that actor in its
native receipt. The backup supervisor similarly has host-owner administration.
Forwarding Manager payloads into these interfaces would turn the service account
into a privileged deputy. Neither a UI role check nor the socket permission matrix
repairs that gap. Existing host-owner interfaces remain outside logical-user role
isolation; no new lower-role route reaches them.

Before enabling: review the role backend, define an unforgeable short-lived broker
authorization envelope scoped to exact action/product/actor/revision/plan/request,
check current authority immediately before native admission, consume once, record
durable uncertain outcomes, and test restart/replay/revocation/concurrent changes in
a disposable installation. Root/service owner remain outside the threat boundary.
Never use opaque caller actor strings as proof. Do not enable an operation merely
because the broker binary builds. No live services, networking, HA or data were
used to qualify this source-only availability response.
