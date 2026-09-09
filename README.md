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

**Budget up to ~1.2 GB of transient memory for each CVE refresh**:
current pro clients materialize the full vulnerability feed to answer
the query — we measured 0.9 GB peak RSS on noble and 1.2 GB on jammy
(upstream issue:
[canonical/ubuntu-pro-client#3613](https://github.com/canonical/ubuntu-pro-client/issues/3613)). On hosts where a resident
workload already claims most of the RAM, that spike can invoke the
kernel OOM killer — and the kernel often picks the workload, not the pro
process. Run with `--pro.cves=false` on such hosts until the upstream
cost comes down; every other metric works without it.

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

Label values are fixed and low cardinality, and every series is always
exported (at 0 when empty) so alerts never deal with absent series. The
label values and starter queries are documented in
[docs/metrics.md](docs/metrics.md).

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

The log entry shape, the CVE log filters, and the snapshot pattern that
lets a dashboard show exactly the current list of one host — including
how unchanged lists are periodically re-logged so log retention never
orphans a snapshot — are documented in [docs/logs.md](docs/logs.md).

## Dashboards and alerts

The [examples](examples/) directory carries two importable Grafana
dashboards — a fleet overview and a single-host drill-down, linked from
the fleet's host table — and starter Prometheus alerting rules covering
a broken exporter, stale data, security-update backlog, ESM-locked fixes
and pending reboots. Everything uses only the standard `instance` label,
and [examples/demo](examples/demo/) runs a three-container fleet with
real data to try it all on.

## Installing

Download the static binary for your architecture (linux amd64 or arm64) from
the [releases page](https://github.com/basecamp/ubuntu_pro_updates_exporter/releases)
and put it on the host. That is the whole install. The project deliberately
ships just the binary; run it under your process supervisor of choice.

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
| `--log.snapshot-interval` | `24h` | Re-log an unchanged list as a fresh snapshot once it is this old (`0` = on change only) |
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

## Design

Why shell out to the pro CLI, why collection is decoupled from serving,
and how failure is kept alertable: [docs/design.md](docs/design.md).

## License

MIT (see `LICENSE`).
