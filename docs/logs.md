# Logs reference

The metrics tell you that updates are pending and how many; the `--log.*`
flags tell you which. This page documents the log shape, the CVE log
filters, and the snapshot pattern that ties log entries to the metrics.

## Flag shape

Every log follows the same flag shape: a boolean `--log.*` flag enables
it, and where a log supports filtering, the filter is a comma-separated
list of the values to include, with a sane default.

Whenever the set changes, the exporter logs one summary entry plus one
entry per item — package, version, pocket and status for updates; the
inventory manifest for installed packages; the package-CVE pairs for CVEs.

## CVE log filters

The CVE log has two filters.

`--log.cves-statuses` picks the fix statuses: `fixed` means a fix exists
that the host has not applied (the action is upgrading, and the entry
names the version and pocket), `vulnerable` means the exposure is
confirmed with no fix released, and `unknown` means Canonical has not
determined fix availability for that package (the action for those two is
mitigating; a dashboard splits them from the fixed entries on the
`fix_status` field). The unknown bucket is typically the largest and
partly reflects gaps in the vulnerability data (for example `-dbg` and
`-dev` packages that are not tracked individually), so dropping it from
the default `fixed,vulnerable,unknown` is the low-noise choice.

`--log.cves-priorities` bounds the volume by Ubuntu CVE priority and
defaults to `high,critical`; the full list of fixable packages regardless
of priority is already what `--log.package-updates` provides. CVEs
without a triaged priority never reach the log; they stay visible in the
aggregate metrics.

Each entry also carries the installed version the pair was evaluated
against (`current_version`) and, when Ubuntu's data has a CVSS
assessment, the CVE's `cvss_score` and `cvss_severity` (omitted
otherwise), so log queries can rank by score rather than by the coarser
priority buckets.

## Snapshots

Per-item entries keep every line small (journald truncates lines around
48KiB) and make the log store queryable line by line: filter by package,
CVE or priority, or turn the entries of one host into a table. Every entry
of a snapshot carries the same `snapshot` field, and the newest snapshot
time per list is exported as
`ubuntu_pro_updates_list_snapshot_timestamp_seconds{list=...}` — so a
dashboard resolves that gauge for a host and filters the log entries with
`snapshot` equal to it to show exactly the current list, including
removals.

Logging only on change would let a log store's retention eventually delete
the only copy of a list that has not changed in a while, leaving the gauge
pointing at a snapshot no store holds. So the exporter also re-logs an
unchanged list as a fresh snapshot once its last snapshot is
`--log.snapshot-interval` old (default 24h). The check runs at refresh
time, so the effective maximum snapshot age is the snapshot interval plus
`--pro.refresh-interval` — with the defaults, 24h + 12h — and refresh
failures extend it further, since only a refresh that produced data can
re-log it. Size the dashboard lookback for that sum plus slack, not for
the snapshot interval alone. An interval comfortably below the refresh
interval re-logs on every refresh; at exact equality the query-duration
jitter can skip alternate refreshes, since the snapshot timestamp is
taken after the queries finish while refreshes tick from their start. The join on `snapshot` still finds
exactly one copy, and the summary entry carries `changed=false` for these
re-logs. The cost is one full list per host per interval; `0` restores
change-only logging.

The [examples README](../examples/README.md#querying-the-logs) shows how
the entries turn into log-store tables, with a Loki query to start from.
