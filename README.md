# ubuntu-pro-updates-exporter

A Prometheus exporter for Ubuntu package update status, based on the machine
readable API of the Ubuntu Pro client
([`pro api u.pro.packages.updates.v1`](https://documentation.ubuntu.com/pro-client/en/latest/references/api/)).

Most apt-based exporters count upgradable packages by parsing apt output or
guessing from repository names. This exporter asks the Ubuntu Pro client
instead. The client classifies every pending update into a pocket
(`standard-security`, `standard-updates`, `esm-apps`, `esm-infra`) and an
update status. One of those statuses is `pending_attach`: a security fix that
exists in Ubuntu's ESM repositories but cannot be installed because the host
is not attached to an Ubuntu Pro subscription. That makes it possible to
alert on the security updates a host is missing, not just the ones it can
install.

No subscription is required. The API endpoints used here work on unattached
hosts, need no root privileges and no network access. They read the local apt
caches, so results are as fresh as the last `apt update`.

## Requirements

- Ubuntu with `ubuntu-advantage-tools` 27.12 or newer. This ships by default
  on all supported releases and provides `pro api u.pro.packages.updates.v1`
  and `u.pro.security.status.reboot_required.v1`.
- Periodic apt metadata refresh (`APT::Periodic::Update-Package-Lists`,
  enabled by default on Ubuntu). The exporter never runs `apt update` itself.

If the pro client is missing or fails, the exporter keeps serving with
`ubuntu_pro_updates_exporter_up` set to 0. It never crashes on a degraded host.

CVE metrics use `u.pro.security.cves.v1`, which exists since pro client 35
and downloads Canonical's public vulnerability data, so it needs network
access and adds a few seconds to each refresh. No subscription is required
for it either. On an older client the exporter logs one warning and
disables CVE collection for the life of the process: upgrade the client
and restart the exporter to enable it. `ubuntu_pro_updates_client_info`
makes that rollout observable.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ubuntu_pro_updates_exporter_up` | gauge | | 1 if the last refresh from the pro client succeeded |
| `ubuntu_pro_updates_pending` | gauge | `pocket`, `status` | Number of pending package updates |
| `ubuntu_pro_updates_download_bytes` | gauge | `pocket` | Total download size of pending updates |
| `ubuntu_pro_updates_reboot_required` | gauge | `state` | Reboot required state, encoded as an enum where the active state is 1 |
| `ubuntu_pro_updates_installed_packages` | gauge | `origin` | Number of installed packages by archive origin |
| `ubuntu_pro_updates_cves` | gauge | `priority`, `fix_status` | Distinct CVEs affecting installed packages (pro client 35 or newer) |
| `ubuntu_pro_updates_cve_fixes` | gauge | `origin` | Package-CVE pairs with an unapplied fix, by fix pocket (pro client 35 or newer) |
| `ubuntu_pro_updates_attached` | gauge | | 1 if the host is attached to an Ubuntu Pro subscription |
| `ubuntu_pro_updates_client_info` | gauge | `version` | Installed pro client version |
| `ubuntu_pro_updates_list_snapshot_timestamp_seconds` | gauge | `list` | Unix time of the newest logged snapshot per on-change list |
| `ubuntu_pro_updates_exporter_last_success_timestamp_seconds` | gauge | | Unix time of the last successful refresh, absent until one succeeds |
| `ubuntu_pro_updates_exporter_query_duration_seconds` | gauge | | Time spent querying the pro client during the last refresh |
| `ubuntu_pro_updates_exporter_build_info` | gauge | `version`, `revision`, `goversion` | Build information |

Label values are fixed and low cardinality. All series are always exported,
at 0 when empty, so alerts never have to deal with absent series.

- `pocket`: `standard-security`, `standard-updates`, `esm-apps`, `esm-infra`
- `status`: `upgrade_available`, `upgrade_available_not_preferred`,
  `pending_attach` (the fix exists in ESM but the host is unattached),
  `pending_enable` (attached, but the ESM service is disabled) and
  `upgrade_unavailable` (attached, but not entitled)
- `state`: `no`, `yes` and `yes-kernel-livepatches-applied` (a reboot is
  pending but Livepatch covers the running kernel)
- `origin` on `installed_packages`: `main`, `universe`, `multiverse`,
  `restricted`, `esm-apps`, `esm-infra`, `third-party`, `unknown`
- `priority`: the Ubuntu CVE priorities `negligible`, `low`, `medium`,
  `high`, `critical`
- `fix_status`: `fixed` (a fix exists that the host has not applied),
  `vulnerable` (no fix released) and `unknown` (fix availability not
  determined for the package); a CVE affecting several packages counts
  once, under its most actionable status
- `origin` on `cve_fixes`: `security`, `updates`, `esm-apps`, `esm-infra`
  (the esm pockets need an Ubuntu Pro subscription)

There is deliberately no total gauge. The sum of `ubuntu_pro_updates_pending`
equals the `num_updates` field of the API, and a gauge named `*_total` would
collide with counter naming conventions.

### Example queries

```promql
# Pending security updates (standard pocket) per host
sum by (instance) (ubuntu_pro_updates_pending{pocket="standard-security"})

# Security fixes a host is missing because it is not attached to Ubuntu Pro
sum by (instance) (ubuntu_pro_updates_pending{status="pending_attach"})

# Hosts needing a reboot, excluding those covered by Livepatch
ubuntu_pro_updates_reboot_required{state="yes"} == 1

# Exporter healthy but data stale for a day
time() - ubuntu_pro_updates_exporter_last_success_timestamp_seconds > 86400
```

## Which packages?

Per-package labeled metrics are intentionally not exposed. A host that has
not been upgraded in a while can easily have several hundred pending updates,
and labels like `package` and `version` would turn those into hundreds of
churning time series per host. Prometheus is not the right store for that
kind of data.

Instead, run with `--log.package-updates` (ideally combined with
`--log.format=json`). Whenever the set of pending updates changes, the
exporter logs one summary entry plus one entry per update with package,
version, pocket and status. The metrics tell you that updates are pending
and how many, the log tells you which. The same pattern powers
`--log.installed-packages` (the inventory manifest) and `--log.cves` (the
package-CVE pairs affecting installed packages).

Every log follows the same flag shape: a boolean `--log.*` flag enables
it, and where a log supports filtering, the filter is a comma-separated
list of the values to include, with a sane default. The CVE log has two
such filters. `--log.cves-statuses` picks the fix statuses: `fixed` means
a fix exists that the host has not applied (the action is upgrading, and
the entry names the version and pocket), `vulnerable` means the exposure
is confirmed with no fix released, and `unknown` means Canonical has not
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
aggregate metrics. Each entry also carries the installed version the
pair was evaluated against (`current_version`) and, when Ubuntu's data
has a CVSS assessment, the CVE's `cvss_score` and `cvss_severity`
(omitted otherwise), so log queries can rank by score rather than by
the coarser priority buckets.

Per-item entries keep every line small (journald truncates lines around
48KiB) and make the log store queryable line by line: filter by package,
CVE or priority, or turn the entries of one host into a table. Every entry
of a snapshot carries the same `snapshot` field, and the newest snapshot
time per list is exported as
`ubuntu_pro_updates_list_snapshot_timestamp_seconds{list=...}` - so a
dashboard resolves that gauge for a host and filters the log entries with
`snapshot` equal to it to show exactly the current list, including
removals.

## Dashboards and alerts

The [examples](examples/) directory carries an importable Grafana
dashboard (fleet stat row, update and CVE trends, a per-host table,
host selector included) and starter Prometheus alerting rules covering
a broken exporter, stale data, security-update backlog, ESM-locked
fixes and pending reboots. Both use only the standard `instance` label.

## Installing

Download the static binary for your architecture (linux amd64 or arm64) from
the [releases page](https://github.com/basecamp/ubuntu_pro_updates_exporter/releases)
and put it on the host. That is the whole install. The project deliberately
ships just the binary; run it under your process supervisor of choice.

## Building

The toolchain is managed with [mise](https://mise.jdx.dev), see `.mise.toml`:

```sh
mise install    # Go and goreleaser
make            # gofmt check, go vet, tests, build
make snapshot   # goreleaser build --snapshot --clean
```

Releases are built with [goreleaser](https://goreleaser.com), see
`.goreleaser.yaml`. CI runs fmt, vet, build and tests on every push and pull
request. Pushing a `v*` tag drafts a GitHub release with the binaries
attached.

## Running

```sh
./ubuntu-pro-updates-exporter --web.listen-address=:10052 --web.telemetry-path=/metrics
```

| Flag | Default | Description |
|---|---|---|
| `--web.listen-address` | `:10052` | Address to expose metrics on |
| `--web.telemetry-path` | `/metrics` | Metrics path |
| `--pro.binary` | `pro` | Ubuntu Pro client executable |
| `--pro.timeout` | `10m` | Timeout per `pro api` invocation |
| `--pro.refresh-interval` | `12h` | How often to refresh data from the pro client |
| `--pro.cves` | `true` | Collect CVE metrics (needs pro client 35 or newer and network access) |
| `--log.format` | `text` | `text` or `json` |
| `--log.package-updates` | `false` | Log the pending update list when it changes |
| `--log.installed-packages` | `false` | Log the installed-package manifest when it changes |
| `--log.cves` | `false` | Log the package-CVE pairs affecting installed packages when they change |
| `--log.cves-statuses` | `fixed,vulnerable,unknown` | Fix statuses the CVE log includes |
| `--log.cves-priorities` | `high,critical` | Ubuntu CVE priorities the CVE log includes |
| `--version` | | Print version and exit |

Update data is refreshed by a background loop every `--pro.refresh-interval`.
Scrapes serve the cached result instantly, so no special scrape timeout is
needed:

```yaml
scrape_configs:
  - job_name: ubuntu_pro_updates
    scrape_interval: 1m
    static_configs:
      - targets: ["myhost:10052"]
```

The exporter needs no root privileges, so run it as an unprivileged user.
When running without a home directory (for example with systemd
`DynamicUser=yes`), point `$HOME` at a writable directory, because the pro
client writes a per-user log under `$HOME/.cache` when invoked unprivileged.

Port 10052 is the port registered for this exporter in the
[Prometheus default port allocations](https://github.com/prometheus/prometheus/wiki/Default-port-allocations).

## Design notes

Why shell out to `pro api`? It is the only stable machine readable interface
of the pro client. The underlying API is an in-process Python library, and
there is no socket or D-Bus service. The CLI prints a versioned JSON envelope
to stdout even on failure, so the exporter parses JSON exclusively, never
exit codes or English text, and surfaces the error codes of the envelope
itself.

Collection is decoupled from serving. A single `pro api` walk of the apt
cache costs seconds of CPU, and on pro client 37 the updates query costs
roughly another 0.6s of CPU per pending update (the client re-opens the
apt cache for each update it classifies), so a host far behind on patches
can spend minutes per refresh. That would make every scrape slow and let
concurrent scrapes pile up pro processes; it is also why `--pro.timeout`
defaults to a generous 10 minutes. The refresh happens in the background,
so the cost is CPU only, never scrape latency. The background loop refreshes the
data instead, and scrapes serve the cached snapshot. The default interval of
12 hours mirrors the cadence of apt-daily, whose timer runs twice a day and
refreshes package lists at most once per day. When a refresh fails, the
detail metrics are dropped rather than served stale, and `ubuntu_pro_updates_exporter_up`
together with `ubuntu_pro_updates_exporter_last_success_timestamp_seconds` keeps failure and
staleness alertable.

The reboot required query is best effort. If it fails while the updates
query succeeds, `ubuntu_pro_updates_exporter_up` stays 1 and only the reboot metric is
omitted.

## License

MIT (see `LICENSE`).
