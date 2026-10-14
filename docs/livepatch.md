# Livepatch hosts

On a host with [Canonical Livepatch](https://ubuntu.com/security/livepatch)
installed, the reboot-required query can fail when the exporter runs as an
unprivileged systemd service. This has been reported on Ubuntu 24.04 and
26.04 with pro client 37.2, both with `DynamicUser=yes` and as a fixed
system user. `ubuntu_pro_updates_reboot_required` is then not exported,
and alerts built on it cannot fire. The other metrics are unaffected.

The exporter logs `querying reboot-required state failed`, and
`ubuntu_pro_updates_exporter_query_success{query="reboot_required"}` is 0.

## Why

On these hosts, `pro api u.pro.security.status.reboot_required.v1` runs the
`canonical-livepatch` snap, and the whole endpoint fails if the snap cannot
start. In the reported setups, snap-confine refused to start it. Under
`DynamicUser=yes` this fails with `snap-confine is packaged without
necessary permissions`, and as a fixed system user it fails with
`... is not a snap cgroup for tag snap.canonical-livepatch...`.

The limitation is in the pro client, not in how the exporter queries it.
The endpoint calls Livepatch twice. The first call, which decides between
`yes` and `yes-kernel-livepatches-applied`, already tolerates the failure
by falling back to `yes`. The second only fills informational fields, and
it is the one that fails the endpoint. Reported upstream in
[canonical/ubuntu-pro-client#3631](https://github.com/canonical/ubuntu-pro-client/issues/3631).

