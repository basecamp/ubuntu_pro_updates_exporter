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

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ubuntu_pro_updates_exporter_up` | gauge | | 1 if the last refresh from the pro client succeeded |
| `ubuntu_pro_updates_pending` | gauge | `pocket`, `status` | Number of pending package updates |
| `ubuntu_pro_updates_download_bytes` | gauge | `pocket` | Total download size of pending updates |
| `ubuntu_pro_updates_reboot_required` | gauge | `state` | Reboot required state, encoded as an enum where the active state is 1 |
| `ubuntu_pro_updates_installed_packages` | gauge | `origin` | Number of installed packages by archive origin |
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
`--log.installed-packages`: the inventory manifest, giving the log store a
package history to look back on (for example when checking which hosts
carried a version a CVE later turned out to affect).

Per-item entries keep every line small (journald truncates lines around
48KiB) and make the log store queryable line by line: filter by package or
version, or turn the entries of one host into a table. Every entry
of a snapshot carries the same `snapshot` field, and the newest snapshot
time per list is exported as
`ubuntu_pro_updates_list_snapshot_timestamp_seconds{list=...}` - so a
dashboard resolves that gauge for a host and filters the log entries with
`snapshot` equal to it to show exactly the current list, including
removals.

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
| `--pro.timeout` | `30s` | Timeout per `pro api` invocation |
| `--pro.refresh-interval` | `12h` | How often to refresh data from the pro client |
| `--log.format` | `text` | `text` or `json` |
| `--log.package-updates` | `false` | Log the pending update list when it changes |
| `--log.installed-packages` | `false` | Log the installed-package manifest when it changes |
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
cache costs seconds of CPU, which would make every scrape slow and let
concurrent scrapes pile up pro processes. The background loop refreshes the
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
