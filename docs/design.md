# Design notes

## Why shell out to `pro api`?

It is the only stable machine readable interface of the pro client. The
underlying API is an in-process Python library, and there is no socket or
D-Bus service. The CLI prints a versioned JSON envelope to stdout even on
failure, so the exporter parses JSON exclusively, never exit codes or
English text, and surfaces the error codes of the envelope itself.

## Collection is decoupled from serving

A single `pro api` walk of the apt cache costs seconds of CPU, and on pro
client 37 the updates query costs roughly another 0.6s of CPU per pending
update (the client re-opens the apt cache for each update it classifies —
[canonical/ubuntu-pro-client#3605](https://github.com/canonical/ubuntu-pro-client/issues/3605)),
so a host far behind on patches can spend minutes per refresh. That would
make every scrape slow and let concurrent scrapes pile up pro processes;
it is also why `--pro.timeout` defaults to a generous 10 minutes.

The background loop refreshes the data instead, and scrapes serve the
cached snapshot. The default interval of 12 hours mirrors the cadence of
apt-daily, whose timer runs twice a day and refreshes package lists at
most once per day. When a refresh fails, the detail metrics are dropped
rather than served stale, and `ubuntu_pro_updates_exporter_up` together
with `ubuntu_pro_updates_exporter_last_success_timestamp_seconds` keeps
failure and staleness alertable.

The reboot required query is best effort. If it fails while the updates
query succeeds, `ubuntu_pro_updates_exporter_up` stays 1 and only the
reboot metric is omitted.
