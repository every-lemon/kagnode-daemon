# Legacy Go adoption draft

Source implemented: read-only inventory, synthetic COPY rehearsal and a typed
future rollback/pinning plan. Production adoption, entrypoint replacement and
rollback execution are unavailable. This is not native qualification or a data
migration. The native fresh installer continues to refuse legacy state.

## Root-local API

`legacy_adoption` is a library API; it is not a socket action or a terminal UI.
All inventory, COPY and rollback-plan calls require effective UID 0. There is no
submitted actor, UID or OAuth-to-Operator mapping, database opening, account
creation, encryption conversion, service restart, network or traffic operation.

```rust
inspect() -> anyhow::Result<Plan>
inspect_fixture(root: &Path) -> anyhow::Result<Plan>
copy_dry_run(plan: &Plan, destination: &Path) -> anyhow::Result<Receipt>
rollback_plan(plan: &Plan) -> anyhow::Result<RollbackPlan>
apply_unavailable() -> anyhow::Result<()> // always refuses
```

`inspect()` uses fixed host paths. It accepts only the reviewed Go 5.0.2 binary
SHA256 `123a036a3112271ed86245650110fbb908e56da5378d40eb5f53093d713daf85`
at `/srv/kagnode/cli/releases/5.0.2-reviewed/kagnode`, with the root-owned
`/usr/bin/kagnode` symlink pointing to that exact absolute path. Unit fragment
hashes are restricted to the separately recorded Core/update lineage. Each
ExecStart must contain exactly `/usr/bin/kagnode`, `core` or `apps` as appropriate,
and either `--root ROOT serve` or `serve --root ROOT`. ROOT is `/srv/kagnode` or
`/srv/kagnode/core`. Unknown lineage or arguments require manual review.

Directory components are opened through checked directory descriptors; reads use
O_NOFOLLOW/O_NONBLOCK, root ownership, single-link regular files, no group/world
writes or special file mode bits, and bounded lengths. Reads compare inode, mode, owner, size, mtime and
ctime before/after and against the named file. The final inventory rereads every
file and entry identity. There is no guarantee of a consistent application
snapshot: active writers cause refusal when observed. This inventory cannot
replace a separately verified application-consistent encrypted recovery set.

The fixed unit fragments, absence of alternate vendor/runtime units and all
drop-in directories, absence of the full native broker/daemon/monitor/backup service and timer family,
legacy controller/broker aliases, partial installation roots and four Rust-store candidates,
and protected `/usr/bin/systemctl` are checked. A bounded five-second/32KiB
systemctl show probe requires loaded/active/running legacy units, no drop-ins,
matching fragment paths, no pending daemon reload and root service identity.
The effective argv must match the fragment. Rust units must be absent/inactive.
The probe seals inherited descriptors at exec, uses its own process group,
checks nonblocking setup and bounds the final pipe drain. The plan binds the
complete returned state; PID/state changes invalidate it.
Type-wide and dash-prefix drop-in hierarchies are refused as well as per-unit
drop-ins. Enable links must be root-owned with exact recognized targets; their
metadata/targets are bound. Only the explicit root-owned merged-/usr vendor alias
is accepted. Unknown override layouts fail closed. No service command is executed.

The two JSON inputs are `/srv/kagnode/manager.json` and
`/srv/kagnode/proxy-manager/state.json`. Each must be a nonempty JSON object.
Only the known top-level manager `panels` and product
`active, adapter, channel, installed_at, source_commit, version` field names
are reported. Values remain private. The complete original bytes are hashed;
no JSON is rewritten or imported. Credential stores are not read or searched;
other product files are not silently claimed inventoried or backed up.

`Plan` schema 1 carries fixture scope (or null for host), complete file identities,
entry target/identity, ancillary link targets/identities, allowlisted JSON field names, exact unit argv, observed
unit states and a SHA256 of canonical serialized fields with the digest empty.
It contains no roles, owner assertion or backup attestation. Callers must retain
and review the actual plan; a digest alone is not production approval.

## Synthetic COPY and receipts

`inspect_fixture` requires an absolute protected private root directory. The
binary must have the exact bytes `KagNode synthetic legacy fixture v1\n`; a real
Go binary is refused in fixture scope. Paths below that directory mirror the
fixed host layout; its entry symlink is inventoried without following it.
Fixture unit fragments accept the same strict argv family. Fixture inspection
never invokes systemctl or asserts real service health. This explicit scope
cannot enable host COPY or activation.

`copy_dry_run` accepts only a fresh synthetic plan and a distinct sibling
output directory. It rejects host plans. The root-controlled parent must already
exist. It creates a 0700 directory, exclusively creates a durable 0600
`intent.json`, then copies the sorted inventory to `copy-00`, `copy-01`, etc.
Source and destination hashes, ownership and modes are checked. Originals are
reread and the full plan is revalidated before exclusively creating durable
0600 `receipt.json`. There is no database initialization or reset. JSON copies
contain synthetic fixture values and stay within the private output directory.

The complete receipt records plan digest, phase, original source identities and
all destination identities. Its destination names correspond to sorted source
keys. An exact completed retry revalidates original state, plan and each output,
then returns the retained receipt without copying again. A changed plan, source
or output is refused. A partial directory, pending intent or missing/invalid
receipt is never retried, overwritten or deleted. Preserve it for inspection;
a new reviewed rehearsal needs a new destination. This is COPY-only durability,
not an encrypted backup or an application-consistent recovery proof.

## Future pinning and rollback contract

`rollback_plan` revalidates the exact observed source plan and returns its digest,
retained old binary path/hash, proposed pin argv, preserved file identities and
original entry target/identity and preserved ancillary links. Activation is always false. Proposed pinning replaces
only the exact ExecStart executable prefix with the retained verified old binary;
it preserves the remaining argv order/root. It does not write a unit.

A future reviewed implementation must first retain and verify the old binary,
entry link, original unit bytes, owner/mode metadata and original enabled/running
states. Before changing `/usr/bin/kagnode`, it must pin both legacy units to the
retained old binary, verify exact rendered fragment hashes and effective loaded
argv, and qualify actual behavior. Merely retaining the old binary while leaving
old units pointed at the new Rust command would break `core` and `apps`.

A future executable rollback needs a separately journaled exact transition
manifest describing every expected post-change unit/entry/service state. It must
refuse mismatches or uncertainty, stop only new services whose identity and
state match that manifest, restore only matching changed entry/units and metadata,
and reverify original effective state. The current original-state plan is not
that transition manifest. Controller databases, legacy manager/product data,
users, certificates and recovery sets must never be deleted as rollback cleanup.
No traffic master, DNS, router, firewall or HA topology operation is included.

Apply remains unavailable until actual independent security review, a verified
consistent encrypted recovery set with tested restoration, native unit pinning,
service/entrypoint execution and full adoption/rollback qualification succeed.
There is no boolean `backup_verified` flag or other caller-controlled unlock.
Existing encryption/format/recovery and emergency access remain unchanged.

## Errors and validation limits

Errors are anyhow results with stable refusal prefixes: `legacy_root_required`,
`legacy_unsafe_directory`, `legacy_unsafe_file`, `legacy_source_changed`,
`legacy_unknown_binary_lineage`, `legacy_unknown_unit_lineage`,
`legacy_unknown_unit_argv`, `legacy_unknown_json_structure`,
`legacy_unexpected_existing_path`, `legacy_probe_*`,
`legacy_effective_argv_mismatch`, `legacy_plan_digest_mismatch`,
`legacy_observed_state_changed`, `legacy_host_copy_unavailable`,
`legacy_destination_separation_required`, `legacy_partial_or_replay_mismatch`,
`legacy_copy_changed` and `legacy_apply_unavailable`. OS/JSON parse errors remain
errors; no refusal falls back to a weaker mode.

Synthetic tests exercise copy/replay, metadata/hash comparisons, malformed and
unknown inputs, argv/root ordering, symlink/hardlink/unsafe ancestry, changed
source/plan/output, deterministic mid-copy mutation, partial refusal and private
receipts. These tests do not prove native production service execution, terminal
owner integration, live JSON consistency, complete legacy parity or rollback
execution. Host inventory is not run as part of this drafting task.
