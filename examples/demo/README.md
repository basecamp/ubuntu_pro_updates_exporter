# Demo stack

A self-contained fleet you can screenshot: three containers built from
deliberately outdated Ubuntu images (dated tags that never move) run
the real `pro` client and the exporter built from this checkout, so
every number on the dashboard is real data — real pending updates, real
CVEs with real CVSS scores — from hosts that don't exist.

| Host     | Base image             | Extras     | Quirk                        |
| -------- | ---------------------- | ---------- | ---------------------------- |
| web-01   | `ubuntu:jammy-20230308`| nginx      | years of pending updates     |
| db-01    | `ubuntu:focal-20230301`| postgresql | reboot flagged, an EOL-ish release |
| cache-01 | `ubuntu:noble-20240605`| redis      | a moderately behind host     |

## Run it

```sh
docker compose up -d --build
```

Then open <http://localhost:3000> (anonymous admin, no login) — the
fleet and host dashboards from `../` are provisioned, with
Prometheus scraping every 15s and the alert rules from
`../prometheus-alerts.yml` loaded (inspect them at
<http://localhost:9090/alerts>). The exporter's JSON logs flow through
Promtail into Loki; in Grafana Explore try:

```logql
{job="ubuntu-pro-updates-exporter", instance="web-01"} | json | msg = `cve`
```

The first refresh downloads Ubuntu's CVE database inside each
container, so give the stack a few minutes before expecting CVE data.
Containers carry no kernel packages, so the kernel CVE panels stay
empty here — on real hosts they light up.
Trend panels only show as much history as the stack has been running —
leave it up for a while if you want the time-series panels to breathe.

The log shipper is Promtail, which Grafana has retired in favor of
Alloy; it still works fine for a throwaway local demo, but don't copy
this part of the stack into anything long-lived.

## Tear down

```sh
docker compose down -v
```
