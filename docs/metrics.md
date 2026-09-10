# Metrics reference

The metric table itself lives in the [README](../README.md#metrics). This
page documents the label values and some starter queries.

Label values are fixed and low cardinality. All series are always
exported, at 0 when empty, so alerts never have to deal with absent
series.

## Label values

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

## Example queries

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
