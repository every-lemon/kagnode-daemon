# Host monitoring and terminal dashboard

This Rust source candidate extends the persistent Daemon service. The released
compatibility CLI remains available; building this candidate does not migrate a
live deployment or activate cluster failover.

## Terminal

Run `kagnode tui` after starting the initialized Daemon service. The charcoal and
blue dashboard shows the local node, CPU, memory, load and a one-hour CPU sample
history. Arrow keys and Enter open application folders. Ctrl+P opens the command
palette; `/` searches applications. Escape goes back. Page Up/Down scroll details.
`--no-mouse` disables mouse capture. Quitting the terminal leaves collection and
managed services running. Offline nodes show unknown/offline, not a false healthy
state or invented zero usage.

Application operations retain the existing reviewed root-broker workflow. This
candidate does not introduce arbitrary terminal commands or package execution.

## Monitoring interfaces

The local terminal API uses `run/control.sock` inside the private controller state
root. Only the state owner or root may connect. Requests are bounded, timed out
and limited to eight simultaneous clients. Metrics work runs away from the async
listener. The optional dashboard may be disabled without disabling collection.

- `kagnode monitor`: current local observation and application detection.
- `kagnode monitor --metric cpu.percent --seconds 3600`: recorded history.
- `kagnode retention`: current policy, revision and presets.
- `kagnode retention --days 7 --revision 0 --confirm-trim`: an explicit policy
  change. Use the actual current revision; shrinking retention or storage budget
  requires confirmation. `--budget-mib` controls the retained-history budget.

Authenticated HTTP clients use `GET /api/v1/monitoring`,
`GET /api/v1/monitoring/history?name=cpu.percent&since=...&until=...`, and
`GET/POST /api/v1/monitoring/retention`. Writes require a recent local administrator
session, same-origin CSRF protection and the current revision. Configuration
changes retain the administrator identity in the audit record.

## Collection and history

Linux procfs is sampled every ten seconds. CPU percentages use counter deltas;
network and disk series use rates. A boot-ID change, counter reset or observation
gap longer than thirty seconds does not create a made-up rate. Missing samples
stay missing. Filesystem capacity, temperature and remote-node health are not yet
collected by this candidate.

History is a private `metrics.sqlite` beside the controller database. Default
retention is thirty days; presets are 2, 5, 7, 30, 90, 180 and 365 days, with custom
1–3650-day policies. Raw samples roll into minute buckets after one day,
fifteen-minute buckets after seven days and hour buckets after ninety days.
Buckets preserve count, average, minimum and maximum. Queries return their
resolution, so a client can distinguish aggregate data from raw observations.

The default retained-data budget is 2 GiB. Cleanup runs each minute and trims old
records when the budget is exceeded, recording trim events. SQLite reusable free
pages, indexes and WAL overhead mean this is not a hard filesystem quota. Retention
changes do not immediately shrink a previously grown database file. Keep disk
headroom and a filesystem quota when a strict physical limit is required.

## Verification and remaining work

Isolated tests cover counter resets, outages, rollup idempotency, peaks, retention
conflicts, CSRF/authorization, private API lifecycle, SIGTERM/restart and terminal
navigation/resizing/restoration. CI also runs ARM64 and Rust 1.88 checks.

This is local-node monitoring. It does not yet provide authenticated remote agents,
SSH pairing, full APT jobs, scheduled reboots or production HA. The separate
maintenance admission function enforces the agreed three-other-service-node floor;
it neither executes a reboot nor accepts untrusted browser observations as proof.
