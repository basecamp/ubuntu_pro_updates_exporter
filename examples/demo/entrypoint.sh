#!/bin/sh
# Demo host entrypoint: freshen apt lists so pending updates reflect
# today's archive, optionally simulate a pending reboot, then run the
# exporter with every log stream enabled so Loki has something to show.
set -u

apt-get update -q || echo "apt-get update failed; using the baked-in lists" >&2

if [ "${DEMO_REBOOT_REQUIRED:-0}" = "1" ]; then
    printf '*** System restart required ***\n' > /var/run/reboot-required
fi

exec /usr/local/bin/ubuntu-pro-updates-exporter \
    -log.format=json \
    -log.cves \
    -log.package-updates \
    -log.installed-packages \
    -pro.refresh-interval="${DEMO_REFRESH_INTERVAL:-10m}" \
    -log.snapshot-interval="${DEMO_SNAPSHOT_INTERVAL:-5m}" \
    "$@"
