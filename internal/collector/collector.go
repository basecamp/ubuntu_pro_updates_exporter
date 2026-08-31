// Package collector implements the prometheus.Collector that exposes Ubuntu
// package-update metrics sourced from the Ubuntu Pro client.
package collector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/basecamp/ubuntu_pro_updates_exporter/internal/proclient"
)

const namespace = "ubuntu_pro_updates"

// exporterSubsystem prefixes the metrics about the exporter itself, keeping
// them apart from the domain metrics.
const exporterSubsystem = "exporter"

type pocketStatus struct {
	pocket, status string
}

type cveBucket struct {
	priority, status string
}

// toSet turns a list-flag value into a membership set.
func toSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}

// Options selects the optional collections and logs.
type Options struct {
	// CollectCVEs queries u.pro.security.cves.v1 on every refresh. The
	// endpoint exists since pro client 35: on an older client the collector
	// logs one warning and disables CVE collection for the life of the
	// process; restart the exporter after upgrading the client.
	CollectCVEs bool
	// LogPackageUpdates logs the full pending-update list whenever it changes.
	LogPackageUpdates bool
	// LogInstalledPackages logs the installed-package manifest whenever it
	// changes.
	LogInstalledPackages bool
	// LogCVEs logs the package-CVE pairs whenever they change; LogCVEsStatuses
	// and LogCVEsPriorities shape what is included.
	LogCVEs bool
	// LogCVEsStatuses lists the fix statuses the CVE log includes: "fixed"
	// (a fix exists the host has not applied), "vulnerable" (the exposure
	// is confirmed and no fix has been released) and "unknown" (fix
	// availability has not been determined for the package).
	LogCVEsStatuses []string
	// LogCVEsPriorities lists the Ubuntu CVE priorities the CVE log
	// includes: negligible, low, medium, high, critical.
	LogCVEsPriorities []string
	// LogSnapshotInterval re-logs an unchanged list (as a new snapshot) once
	// it has gone this long without being logged, so a log store with
	// retention always holds the current list. Zero logs on change only.
	LogSnapshotInterval time.Duration
}

// snapshot is the cached result of one refresh cycle. Detail fields are nil
// when their query failed, so stale data is dropped rather than served as
// fresh.
type snapshot struct {
	updates       *proclient.PackageUpdates
	reboot        *proclient.RebootRequired
	installed     *proclient.InstalledSummary
	cves          *proclient.CVEData
	attached      *bool
	clientVersion string
	// ok records whether the last package-updates query succeeded.
	ok bool
	// duration is the wall time of the last refresh, in seconds.
	duration float64
	// lastSuccess is the unix time of the last successful refresh, 0 if never.
	lastSuccess float64
	// refreshed is true once at least one refresh attempt has completed.
	refreshed bool
}

// Collector serves metrics from a cached snapshot that a background loop
// (Run) refreshes by querying the pro client.
//
// Collection is decoupled from serving because the pro client's apt-cache
// walk takes seconds of CPU per invocation (and the CVE evaluation several
// more): refreshing on a timer keeps scrapes instant and stops concurrent
// scrapes from each spawning pro processes. Freshness is governed by the
// refresh interval and observable via
// ubuntu_pro_updates_exporter_last_success_timestamp_seconds.
type Collector struct {
	client proclient.Client
	logger *slog.Logger
	opts   Options

	up                *prometheus.Desc
	updatesPending    *prometheus.Desc
	downloadBytes     *prometheus.Desc
	rebootRequired    *prometheus.Desc
	installedPackages *prometheus.Desc
	cves              *prometheus.Desc
	cveFixes          *prometheus.Desc
	attached          *prometheus.Desc
	clientInfo        *prometheus.Desc
	listSnapshot      *prometheus.Desc
	lastSuccess       *prometheus.Desc
	queryDuration     *prometheus.Desc

	// now allows tests to fix the clock.
	now func() time.Time

	mu              sync.Mutex
	snap            snapshot
	loggedUpdates   [32]byte // fingerprint of the last logged update set
	loggedInstalled [32]byte // fingerprint of the last logged manifest
	loggedCVEs      [32]byte // fingerprint of the last logged CVE pair set
	// listSnapshots records, per list, the timestamp of the newest logged
	// snapshot; it anchors dashboards to exactly the latest list and paces
	// the periodic re-logging of unchanged lists.
	listSnapshots  map[string]int64
	cveUnsupported bool
}

// New returns a Collector reading from client. Call Run (or Refresh) to
// populate it; until then it serves only ubuntu_pro_updates_exporter_up 0.
func New(client proclient.Client, logger *slog.Logger, opts Options) *Collector {
	return &Collector{
		client:        client,
		logger:        logger,
		opts:          opts,
		now:           time.Now,
		listSnapshots: make(map[string]int64),
		up: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, exporterSubsystem, "up"),
			"Whether the last refresh of package updates from the Ubuntu Pro client succeeded.",
			nil, nil),
		updatesPending: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "pending"),
			"Number of pending package updates, by pocket and update status.",
			[]string{"pocket", "status"}, nil),
		downloadBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "download_bytes"),
			"Total download size of pending package updates, by pocket.",
			[]string{"pocket"}, nil),
		rebootRequired: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "reboot_required"),
			"Reboot-required state of the host; the active state has value 1. "+
				"State yes-kernel-livepatches-applied means a reboot is pending but Livepatch covers the running kernel.",
			[]string{"state"}, nil),
		installedPackages: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "installed_packages"),
			"Number of installed packages, by archive origin.",
			[]string{"origin"}, nil),
		cves: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "cves"),
			"Number of distinct CVEs affecting installed packages, by priority and fix status. "+
				"A CVE counts as fixed when a fix exists for at least one of its affected packages; "+
				"absent on pro clients older than 35.",
			[]string{"priority", "fix_status"}, nil),
		cveFixes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "cve_fixes"),
			"Number of package-CVE pairs with a released fix this host has not applied, by the "+
				"pocket the fix comes from; esm pockets need an Ubuntu Pro subscription. Absent on "+
				"pro clients older than 35.",
			[]string{"origin"}, nil),
		attached: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "attached"),
			"Whether the host is attached to an Ubuntu Pro subscription.",
			nil, nil),
		clientInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "client_info"),
			"Installed Ubuntu Pro client version. CVE metrics need version 35 or newer.",
			[]string{"version"}, nil),
		listSnapshot: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "list_snapshot_timestamp_seconds"),
			"Unix time of the newest logged snapshot per list; every log line of "+
				"that snapshot carries the same value in its snapshot field, anchoring dashboards "+
				"to exactly the latest list. Absent until a list first logs.",
			[]string{"list"}, nil),
		lastSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, exporterSubsystem, "last_success_timestamp_seconds"),
			"Unix time of the last successful package-updates refresh; absent until one succeeds.",
			nil, nil),
		queryDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, exporterSubsystem, "query_duration_seconds"),
			"Time spent querying the Ubuntu Pro client during the last refresh.",
			nil, nil),
	}
}

// Run refreshes immediately and then on every interval tick until ctx is
// cancelled. It is meant to be started as a goroutine from main.
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		c.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Refresh queries the pro client once and replaces the cached snapshot.
// It never runs during a scrape. Everything except the package-updates query
// is best effort: a failure is logged and its metrics omitted, without taking
// ubuntu_pro_updates_exporter_up down.
func (c *Collector) Refresh(ctx context.Context) {
	start := c.now()

	updates, err := c.client.PackageUpdates(ctx)
	if err != nil {
		c.logger.Error("querying package updates failed", "err", err)
	}

	reboot, rebootErr := c.client.RebootRequired(ctx)
	if rebootErr != nil {
		c.logger.Warn("querying reboot-required state failed", "err", rebootErr)
	}

	installed, installedErr := c.client.InstalledSummary(ctx)
	if installedErr != nil {
		c.logger.Warn("querying installed-package summary failed", "err", installedErr)
	}

	var attached *bool
	if att, attErr := c.client.IsAttached(ctx); attErr != nil {
		c.logger.Warn("querying attach status failed", "err", attErr)
	} else {
		attached = &att
	}

	clientVersion, versionErr := c.client.ClientVersion(ctx)
	if versionErr != nil {
		c.logger.Warn("querying pro client version failed", "err", versionErr)
	}

	cves := c.refreshCVEs(ctx)

	// The manifest is only used for logging; skip the query when disabled.
	var manifest []proclient.InstalledPackage
	if c.opts.LogInstalledPackages {
		var manifestErr error
		manifest, manifestErr = c.client.PackageManifest(ctx)
		if manifestErr != nil {
			c.logger.Warn("querying package manifest failed", "err", manifestErr)
		}
	}

	c.mu.Lock()
	c.snap.refreshed = true
	c.snap.duration = c.now().Sub(start).Seconds()
	c.snap.updates = updates
	c.snap.reboot = reboot
	c.snap.installed = installed
	c.snap.cves = cves
	c.snap.attached = attached
	c.snap.clientVersion = clientVersion
	c.snap.ok = updates != nil
	if updates != nil {
		c.snap.lastSuccess = float64(c.now().Unix())
	}
	c.mu.Unlock()

	if updates != nil {
		c.maybeLogUpdates(updates)
	}
	if manifest != nil {
		c.maybeLogInstalled(manifest)
	}
	if cves != nil {
		c.maybeLogCVEs(cves)
	}
}

// refreshCVEs queries the CVE endpoint. When the installed client does not
// provide it (older than 35), CVE collection is disabled for the life of the
// process after a single warning; restart the exporter once the client is
// upgraded. Transient failures keep being retried on the normal cadence.
func (c *Collector) refreshCVEs(ctx context.Context) *proclient.CVEData {
	if !c.opts.CollectCVEs {
		return nil
	}

	c.mu.Lock()
	unsupported := c.cveUnsupported
	c.mu.Unlock()
	if unsupported {
		return nil
	}

	cves, err := c.client.CVEs(ctx)
	if err == nil {
		return cves
	}

	if proclient.IsUnsupported(err) {
		c.mu.Lock()
		c.cveUnsupported = true
		c.mu.Unlock()
		c.logger.Warn("pro client does not provide the CVE endpoint; CVE collection is disabled. Upgrade the client to 35 or newer and restart the exporter",
			"endpoint", "u.pro.security.cves.v1")
		return nil
	}

	c.logger.Warn("querying CVEs failed", "err", err)
	return nil
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.updatesPending
	ch <- c.downloadBytes
	ch <- c.rebootRequired
	ch <- c.installedPackages
	ch <- c.cves
	ch <- c.cveFixes
	ch <- c.attached
	ch <- c.clientInfo
	ch <- c.listSnapshot
	ch <- c.lastSuccess
	ch <- c.queryDuration
}

// Collect implements prometheus.Collector. It serves the cached snapshot and
// must never panic: before the first refresh, or after a failed one, it
// degrades to ubuntu_pro_updates_exporter_up 0 with the detail metrics
// absent.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	snap := c.snap
	listSnapshots := make(map[string]int64, len(c.listSnapshots))
	for list, ts := range c.listSnapshots {
		listSnapshots[list] = ts
	}
	c.mu.Unlock()

	if !snap.refreshed {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}

	for list, ts := range listSnapshots {
		ch <- prometheus.MustNewConstMetric(c.listSnapshot, prometheus.GaugeValue, float64(ts), list)
	}

	ch <- prometheus.MustNewConstMetric(c.queryDuration, prometheus.GaugeValue, snap.duration)
	if snap.lastSuccess > 0 {
		ch <- prometheus.MustNewConstMetric(c.lastSuccess, prometheus.GaugeValue, snap.lastSuccess)
	}
	if snap.reboot != nil {
		c.collectReboot(ch, snap.reboot)
	}
	if snap.installed != nil {
		c.collectInstalled(ch, snap.installed)
	}
	if snap.cves != nil {
		c.collectCVEs(ch, snap.cves)
	}
	if snap.attached != nil {
		v := 0.0
		if *snap.attached {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.attached, prometheus.GaugeValue, v)
	}
	if snap.clientVersion != "" {
		ch <- prometheus.MustNewConstMetric(c.clientInfo, prometheus.GaugeValue, 1, snap.clientVersion)
	}
	if !snap.ok {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)
	c.collectUpdates(ch, snap.updates)
}

func (c *Collector) collectUpdates(ch chan<- prometheus.Metric, pu *proclient.PackageUpdates) {
	// Pre-seed every known pocket/status combination so series exist at 0
	// instead of disappearing, which keeps dashboards and alerts simple.
	counts := make(map[pocketStatus]int)
	sizes := make(map[string]int64)
	for _, p := range proclient.Pockets {
		sizes[p] = 0
		for _, s := range proclient.Statuses {
			counts[pocketStatus{p, s}] = 0
		}
	}
	total := 0
	for _, u := range pu.Updates {
		// Unknown pockets or statuses from future pro client versions get
		// their own series rather than being dropped.
		counts[pocketStatus{u.ProvidedBy, u.Status}]++
		sizes[u.ProvidedBy] += u.DownloadSize
		total++
	}
	if total != pu.Summary.NumUpdates {
		c.logger.Warn("pro api summary disagrees with its updates list",
			"summary_num_updates", pu.Summary.NumUpdates, "updates_len", total)
	}

	for ps, n := range counts {
		ch <- prometheus.MustNewConstMetric(c.updatesPending, prometheus.GaugeValue,
			float64(n), ps.pocket, ps.status)
	}
	for pocket, size := range sizes {
		ch <- prometheus.MustNewConstMetric(c.downloadBytes, prometheus.GaugeValue,
			float64(size), pocket)
	}
}

func (c *Collector) collectReboot(ch chan<- prometheus.Metric, rr *proclient.RebootRequired) {
	known := false
	for _, state := range proclient.RebootStates {
		v := 0.0
		if rr.RebootRequired == state {
			v = 1
			known = true
		}
		ch <- prometheus.MustNewConstMetric(c.rebootRequired, prometheus.GaugeValue, v, state)
	}
	if !known {
		c.logger.Warn("unknown reboot_required state", "state", rr.RebootRequired)
		ch <- prometheus.MustNewConstMetric(c.rebootRequired, prometheus.GaugeValue, 1, rr.RebootRequired)
	}
}

func (c *Collector) collectInstalled(ch chan<- prometheus.Metric, s *proclient.InstalledSummary) {
	counts := map[string]int{
		"main":        s.NumMainPackages,
		"universe":    s.NumUniversePackages,
		"multiverse":  s.NumMultiversePackages,
		"restricted":  s.NumRestrictedPackages,
		"esm-apps":    s.NumESMAppsPackages,
		"esm-infra":   s.NumESMInfraPackages,
		"third-party": s.NumThirdPartyPackages,
		"unknown":     s.NumUnknownPackages,
	}
	for _, origin := range proclient.PackageOrigins {
		ch <- prometheus.MustNewConstMetric(c.installedPackages, prometheus.GaugeValue,
			float64(counts[origin]), origin)
	}
}

// statusRank orders fix statuses by actionability, so a CVE affecting several
// packages is counted once under its most actionable status.
var statusRank = map[string]int{"unknown": 0, "vulnerable": 1, "fixed": 2}

func (c *Collector) collectCVEs(ch chan<- prometheus.Metric, data *proclient.CVEData) {
	// Roll package-CVE pairs up to distinct CVEs, keeping the most actionable
	// fix status seen across a CVE's packages.
	cveStatus := make(map[string]string)
	fixPairs := make(map[string]int)
	for _, origin := range proclient.FixOrigins {
		fixPairs[origin] = 0
	}

	for _, pkg := range data.Packages {
		for _, fix := range pkg.CVEs {
			status := fix.FixStatus
			if _, ok := statusRank[status]; !ok {
				status = "unknown"
			}
			if prev, seen := cveStatus[fix.Name]; !seen || statusRank[status] > statusRank[prev] {
				cveStatus[fix.Name] = status
			}
			if fix.FixStatus == "fixed" {
				fixPairs[fix.FixOrigin]++
			}
		}
	}

	counts := make(map[cveBucket]int)
	for _, p := range proclient.CVEPriorities {
		for _, s := range proclient.CVEFixStatuses {
			counts[cveBucket{p, s}] = 0
		}
	}
	for name, status := range cveStatus {
		priority := data.CVEs[name].Priority
		if priority == "" {
			priority = "unknown"
		}
		counts[cveBucket{priority, status}]++
	}

	for b, n := range counts {
		ch <- prometheus.MustNewConstMetric(c.cves, prometheus.GaugeValue,
			float64(n), b.priority, b.status)
	}
	for origin, n := range fixPairs {
		ch <- prometheus.MustNewConstMetric(c.cveFixes, prometheus.GaugeValue,
			float64(n), origin)
	}
}

// maybeLog fingerprints lines and reports whether the list should be logged
// now: it emits on a change since the last logged set, and, when a snapshot
// interval is configured, also once the last snapshot is that old -- so a log
// store with retention keeps holding the current list even when nothing
// changes. Either way it records the snapshot timestamp for the list, so the
// list-snapshot gauge and the log lines carry the same anchor value. changed
// tells the two cases apart for the summary entry.
func (c *Collector) maybeLog(slot *[32]byte, list string, ts int64, lines []string) (emit, changed bool) {
	sort.Strings(lines)
	fingerprint := sha256.Sum256([]byte(strings.Join(lines, "\n")))

	c.mu.Lock()
	defer c.mu.Unlock()
	if fingerprint != *slot {
		*slot = fingerprint
		c.listSnapshots[list] = ts
		return true, true
	}
	last, logged := c.listSnapshots[list]
	if c.opts.LogSnapshotInterval > 0 && logged && ts-last >= int64(c.opts.LogSnapshotInterval.Seconds()) {
		c.listSnapshots[list] = ts
		return true, false
	}
	return false, false
}

// maybeLogUpdates logs the pending updates when the set changes: one summary
// entry plus one entry per update, each line small enough for journald and
// each carrying the same snapshot timestamp. Filtering the log store on
// snapshot = the list-snapshot gauge value yields exactly the current list.
// With a snapshot interval, an unchanged list is re-logged as a fresh
// snapshot once it is that old (see maybeLog); the same applies to the
// installed-package and CVE logs below.
func (c *Collector) maybeLogUpdates(pu *proclient.PackageUpdates) {
	if !c.opts.LogPackageUpdates {
		return
	}

	lines := make([]string, 0, len(pu.Updates))
	for _, u := range pu.Updates {
		lines = append(lines, fmt.Sprintf("%s %s %s %s", u.Package, u.Version, u.ProvidedBy, u.Status))
	}
	ts := c.now().Unix()
	emit, changed := c.maybeLog(&c.loggedUpdates, "pending", ts, lines)
	if !emit {
		return
	}

	c.logger.Info("pending package updates changed", "snapshot", ts, "num_updates", len(pu.Updates), "changed", changed)
	for _, u := range pu.Updates {
		c.logger.Info("pending package update", "snapshot", ts,
			"package", u.Package,
			"version", u.Version,
			"pocket", u.ProvidedBy,
			"status", u.Status)
	}
}

// maybeLogInstalled logs the installed-package manifest when it changes, so
// the inventory history lives in the log store for CVE lookback.
func (c *Collector) maybeLogInstalled(manifest []proclient.InstalledPackage) {
	lines := make([]string, 0, len(manifest))
	for _, p := range manifest {
		lines = append(lines, p.Package+" "+p.Version)
	}
	ts := c.now().Unix()
	emit, changed := c.maybeLog(&c.loggedInstalled, "installed", ts, lines)
	if !emit {
		return
	}

	c.logger.Info("installed packages changed", "snapshot", ts, "num_installed", len(manifest), "changed", changed)
	for _, p := range manifest {
		c.logger.Info("installed package", "snapshot", ts,
			"package", p.Package,
			"version", p.Version)
	}
}

type cveLogEntry struct {
	Package        string   `json:"package"`
	CurrentVersion string   `json:"current_version"`
	CVE            string   `json:"cve"`
	Priority       string   `json:"priority"`
	FixStatus      string   `json:"fix_status"`
	FixVersion     string   `json:"fix_version"`
	FixOrigin      string   `json:"fix_origin"`
	CVSSScore      *float64 `json:"cvss_score"`
	CVSSSeverity   string   `json:"cvss_severity"`
}

// maybeLogCVEs logs the package-CVE pairs whose fix status and priority are
// configured for inclusion, whenever the set changes. An entry with fix
// status fixed names the version and pocket to upgrade to; vulnerable
// (confirmed, no fix released) and unknown (fix availability not determined
// for the package) entries are the ones to mitigate. Pairs whose CVE has no
// triaged priority match no configured value and never reach the log, but
// remain visible in the aggregate metrics.
func (c *Collector) maybeLogCVEs(data *proclient.CVEData) {
	if !c.opts.LogCVEs {
		return
	}
	statuses := toSet(c.opts.LogCVEsStatuses)
	priorities := toSet(c.opts.LogCVEsPriorities)

	var pairs []cveLogEntry
	for name, pkg := range data.Packages {
		for _, fix := range pkg.CVEs {
			if !statuses[fix.FixStatus] {
				continue
			}
			info := data.CVEs[fix.Name]
			if !priorities[info.Priority] {
				continue
			}
			pairs = append(pairs, cveLogEntry{
				Package:        name,
				CurrentVersion: pkg.CurrentVersion,
				CVE:            fix.Name,
				Priority:       info.Priority,
				FixStatus:      fix.FixStatus,
				FixVersion:     fix.FixVersion,
				FixOrigin:      fix.FixOrigin,
				CVSSScore:      info.CVSSScore,
				CVSSSeverity:   info.CVSSSeverity,
			})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Package != pairs[j].Package {
			return pairs[i].Package < pairs[j].Package
		}
		return pairs[i].CVE < pairs[j].CVE
	})

	lines := make([]string, 0, len(pairs))
	for _, p := range pairs {
		lines = append(lines, p.Package+" "+p.CVE+" "+p.FixStatus+" "+p.FixVersion)
	}
	ts := c.now().Unix()
	emit, changed := c.maybeLog(&c.loggedCVEs, "cves", ts, lines)
	if !emit {
		return
	}

	c.logger.Info("CVEs changed", "snapshot", ts, "num_pairs", len(pairs), "changed", changed)
	for _, p := range pairs {
		args := []any{"snapshot", ts,
			"package", p.Package,
			"current_version", p.CurrentVersion,
			"cve", p.CVE,
			"priority", p.Priority,
			"fix_status", p.FixStatus,
			"fix_version", p.FixVersion,
			"fix_origin", p.FixOrigin,
		}
		// CVEs without a CVSS assessment omit the score fields rather than
		// logging a misleading 0.
		if p.CVSSScore != nil {
			args = append(args, "cvss_score", *p.CVSSScore, "cvss_severity", p.CVSSSeverity)
		}
		c.logger.Info("cve", args...)
	}
}
