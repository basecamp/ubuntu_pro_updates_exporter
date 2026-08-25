# Examples

Starting points for wiring the exporter into a Prometheus and Grafana
setup. Both files use only the standard `instance` label, so they work
with a plain static scrape config out of the box.

## Grafana dashboard

`grafana-dashboard.json` is a standard importable dashboard: in Grafana
go to Dashboards, Import, upload the file and pick your Prometheus data
source. It has a host selector (multi-select, filled from the exporter's
own metrics), a fleet stat row, trends for pending updates, CVE exposure
and installed-package origins, and a per-host status table.

## Prometheus alerts

`prometheus-alerts.yml` carries starter alerting rules: exporter broken,
data stale, security-update backlog, ESM-locked security fixes, and
reboot required. Validate and tune before shipping:

```sh
promtool check rules examples/prometheus-alerts.yml
```

The thresholds are deliberately conservative (`for: 3d` on the backlog,
`for: 7d` on the reboot) so they surface debt without paging anyone; a
CVE metric alert like
`sum by (instance) (ubuntu_pro_updates_cves{fix_status="fixed", priority="critical"}) > 0`
is a natural next step once you trust the data.

## Querying the logs

The `--log.*` flags emit one JSON entry per list item on change, which
any log pipeline that parses JSON fields (Loki, Elasticsearch, and
friends) can turn into per-host tables: filter entries by their `msg`
field (`pending package update`, `installed package`, `cve`), and use
the shared `snapshot` field to pin exactly one version of a list. The
newest snapshot per list is exported as
`ubuntu_pro_updates_list_snapshot_timestamp_seconds{list=...}`, so a
dashboard can resolve that gauge and filter the log entries to it. In
Loki, assuming the JSON fields are parsed into labels or structured
metadata, the current CVE list of one host ranked by CVSS score looks
like:

```logql
{job="my-log-pipeline"} | msg = `cve` | instance = `myhost` | snapshot = `<value of the gauge>`
```

The exact selectors depend on how your pipeline labels journald units;
the entries themselves need no transformation, they are flat JSON.
