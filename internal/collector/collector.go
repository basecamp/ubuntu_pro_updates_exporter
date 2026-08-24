// Package collector implements the prometheus.Collector that exposes Ubuntu
// package-update metrics sourced from the Ubuntu Pro client.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// logChunkSize bounds one log entry's list payload so entries survive
// journald's line limit (about 48KiB) intact. A var so tests can shrink it.
var logChunkSize = 200

type pocketStatus struct {
	pocket, status string
}

type cveBucket struct {
	priority, status string
}

// priorityRank orders the Ubuntu CVE priorities; unknown or untriaged
// priorities rank below negligible.
func priorityRank(priority string) int {
	switch priority {
	case "negligible":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return -1
	}
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
	// LogCVEs logs the fixable package-CVE pairs whenever they change.
	LogCVEs bool
	// LogCVEsInEffect also logs the in-effect package-CVE pairs (the host is
	// affected and no fix has been released) whenever they change, so
	// operators can mitigate while a fix is pending. Untriaged CVEs are not
	// logged.
	LogCVEsInEffect bool
	// LogCVEsMinPriority is the minimum Ubuntu CVE priority for the
	// in-effect log: negligible, low, medium, high or critical.
	LogCVEsMinPriority string
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
	lastSuccess       *prometheus.Desc
	queryDuration     *prometheus.Desc

	// now allows tests to fix the clock.
	now func() time.Time

	mu              sync.Mutex
	snap            snapshot
	loggedUpdates   [32]byte // fingerprint of the last logged update set
	loggedInstalled [32]byte // fingerprint of the last logged manifest
	loggedFixable   [32]byte // fingerprint of the last logged fixable set
	loggedInEffect  [32]byte // fingerprint of the last logged in-effect set
	cveUnsupported  bool
}

// New returns a Collector reading from client. Call Run (or Refresh) to
// populate it; until then it serves only ubuntu_pro_updates_exporter_up 0.
func New(client proclient.Client, logger *slog.Logger, opts Options) *Collector {
	return &Collector{
		client: client,
		logger: logger,
		opts:   opts,
		now:    time.Now,
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
		c.maybeLogFixableCVEs(cves)
		c.maybeLogInEffectCVEs(cves)
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
	c.mu.Unlock()

	if !snap.refreshed {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
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

// maybeLog fingerprints lines and reports whether the set changed since the
// last time this fingerprint slot logged, along with a short change id that
// ties the chunked entries of one change together.
func (c *Collector) maybeLog(slot *[32]byte, lines []string) (bool, string) {
	sort.Strings(lines)
	fingerprint := sha256.Sum256([]byte(strings.Join(lines, "\n")))

	c.mu.Lock()
	defer c.mu.Unlock()
	if fingerprint == *slot {
		return false, ""
	}
	*slot = fingerprint
	return true, hex.EncodeToString(fingerprint[:4])
}

// logList emits one log entry per chunk of logChunkSize items, so large lists
// survive journald's line limit. Entries of the same change share the change
// id and carry part/parts numbering for reassembly in the log store.
func logList[T any](logger *slog.Logger, msg, changeID, totalKey string, total int, listKey string, items []T) {
	parts := (len(items) + logChunkSize - 1) / logChunkSize
	if parts == 0 {
		parts = 1
	}
	for i := 0; i < parts; i++ {
		lo := i * logChunkSize
		hi := min(lo+logChunkSize, len(items))
		logger.Info(msg,
			"change", changeID,
			"part", i+1,
			"parts", parts,
			totalKey, total,
			listKey, items[lo:hi])
	}
}

// maybeLogUpdates logs the full pending-update list when it changes, giving
// operators the per-package detail that would be too high-cardinality as
// labeled metrics.
func (c *Collector) maybeLogUpdates(pu *proclient.PackageUpdates) {
	if !c.opts.LogPackageUpdates {
		return
	}

	lines := make([]string, 0, len(pu.Updates))
	for _, u := range pu.Updates {
		lines = append(lines, fmt.Sprintf("%s %s %s %s", u.Package, u.Version, u.ProvidedBy, u.Status))
	}
	changed, id := c.maybeLog(&c.loggedUpdates, lines)
	if !changed {
		return
	}

	logList(c.logger, "pending package updates changed", id,
		"num_updates", len(pu.Updates), "updates", pu.Updates)
}

// maybeLogInstalled logs the installed-package manifest when it changes, so
// the inventory history lives in the log store for CVE lookback.
func (c *Collector) maybeLogInstalled(manifest []proclient.InstalledPackage) {
	lines := make([]string, 0, len(manifest))
	for _, p := range manifest {
		lines = append(lines, p.Package+" "+p.Version)
	}
	changed, id := c.maybeLog(&c.loggedInstalled, lines)
	if !changed {
		return
	}

	logList(c.logger, "installed packages changed", id,
		"num_installed", len(manifest), "packages", manifest)
}

type cveFixLogEntry struct {
	Package    string `json:"package"`
	CVE        string `json:"cve"`
	Priority   string `json:"priority"`
	FixVersion string `json:"fix_version"`
	FixOrigin  string `json:"fix_origin"`
}

// maybeLogFixableCVEs logs the fixable package-CVE pairs when they change:
// the direct action here is applying the fix.
func (c *Collector) maybeLogFixableCVEs(data *proclient.CVEData) {
	if !c.opts.LogCVEs {
		return
	}

	var fixes []cveFixLogEntry
	for name, pkg := range data.Packages {
		for _, fix := range pkg.CVEs {
			if fix.FixStatus != "fixed" {
				continue
			}
			fixes = append(fixes, cveFixLogEntry{
				Package:    name,
				CVE:        fix.Name,
				Priority:   data.CVEs[fix.Name].Priority,
				FixVersion: fix.FixVersion,
				FixOrigin:  fix.FixOrigin,
			})
		}
	}
	sort.Slice(fixes, func(i, j int) bool {
		if fixes[i].Package != fixes[j].Package {
			return fixes[i].Package < fixes[j].Package
		}
		return fixes[i].CVE < fixes[j].CVE
	})

	lines := make([]string, 0, len(fixes))
	for _, f := range fixes {
		lines = append(lines, f.Package+" "+f.CVE+" "+f.FixVersion)
	}
	changed, id := c.maybeLog(&c.loggedFixable, lines)
	if !changed {
		return
	}

	logList(c.logger, "fixable CVEs changed", id,
		"num_fixes", len(fixes), "fixes", fixes)
}

type cveInEffectLogEntry struct {
	Package  string `json:"package"`
	CVE      string `json:"cve"`
	Priority string `json:"priority"`
}

// maybeLogInEffectCVEs logs the package-CVE pairs the host is exposed to with
// no released fix, at or above the configured priority, so operators can
// mitigate in the meantime. Untriaged pairs (unknown fix status or unknown
// priority) are excluded: there is nothing actionable in them yet, and they
// remain visible in the aggregate metrics.
func (c *Collector) maybeLogInEffectCVEs(data *proclient.CVEData) {
	if !c.opts.LogCVEsInEffect {
		return
	}
	minRank := priorityRank(c.opts.LogCVEsMinPriority)

	var pairs []cveInEffectLogEntry
	for name, pkg := range data.Packages {
		for _, fix := range pkg.CVEs {
			if fix.FixStatus != "vulnerable" {
				continue
			}
			priority := data.CVEs[fix.Name].Priority
			if priorityRank(priority) < minRank {
				continue
			}
			pairs = append(pairs, cveInEffectLogEntry{
				Package:  name,
				CVE:      fix.Name,
				Priority: priority,
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
		lines = append(lines, p.Package+" "+p.CVE)
	}
	changed, id := c.maybeLog(&c.loggedInEffect, lines)
	if !changed {
		return
	}

	logList(c.logger, "in-effect CVEs changed", id,
		"num_cves", len(pairs), "cves", pairs)
}
