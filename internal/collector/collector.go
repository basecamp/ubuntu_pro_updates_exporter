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

const namespace = "ubuntu_pro"

type pocketStatus struct {
	pocket, status string
}

// snapshot is the cached result of one refresh cycle.
type snapshot struct {
	// updates is nil when the last refresh failed; the detail metrics are
	// then omitted rather than serving stale counts as if they were fresh.
	updates *proclient.PackageUpdates
	reboot  *proclient.RebootRequired
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
// walk takes seconds of CPU per invocation: refreshing on a timer keeps
// scrapes instant and stops concurrent scrapes from each spawning pro
// processes. Freshness is governed by the refresh interval and observable
// via ubuntu_pro_last_success_timestamp_seconds.
type Collector struct {
	client      proclient.Client
	logger      *slog.Logger
	logPackages bool

	up             *prometheus.Desc
	updatesPending *prometheus.Desc
	downloadBytes  *prometheus.Desc
	rebootRequired *prometheus.Desc
	lastSuccess    *prometheus.Desc
	queryDuration  *prometheus.Desc

	// now allows tests to fix the clock.
	now func() time.Time

	mu            sync.Mutex
	snap          snapshot
	loggedUpdates [32]byte // fingerprint of the last logged package set
}

// New returns a Collector reading from client. Call Run (or Refresh) to
// populate it; until then it serves only ubuntu_pro_up 0. If logPackages is
// true, the full list of pending updates is logged whenever it changes, as
// the low-cardinality answer to "which packages?" (see the README).
func New(client proclient.Client, logger *slog.Logger, logPackages bool) *Collector {
	return &Collector{
		client:      client,
		logger:      logger,
		logPackages: logPackages,
		now:         time.Now,
		up: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "up"),
			"Whether the last refresh of package updates from the Ubuntu Pro client succeeded.",
			nil, nil),
		updatesPending: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "updates", "pending"),
			"Number of pending package updates, by pocket and update status.",
			[]string{"pocket", "status"}, nil),
		downloadBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "updates", "download_bytes"),
			"Total download size of pending package updates, by pocket.",
			[]string{"pocket"}, nil),
		rebootRequired: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "reboot_required"),
			"Reboot-required state of the host; the active state has value 1. "+
				"State yes-kernel-livepatches-applied means a reboot is pending but Livepatch covers the running kernel.",
			[]string{"state"}, nil),
		lastSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "last_success_timestamp_seconds"),
			"Unix time of the last successful package-updates refresh; absent until one succeeds.",
			nil, nil),
		queryDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "query_duration_seconds"),
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
// It never runs during a scrape.
func (c *Collector) Refresh(ctx context.Context) {
	start := c.now()

	updates, err := c.client.PackageUpdates(ctx)
	if err != nil {
		c.logger.Error("querying package updates failed", "err", err)
	}

	// Reboot state is best effort: its failure is logged but does not take
	// ubuntu_pro_up down with it.
	reboot, rebootErr := c.client.RebootRequired(ctx)
	if rebootErr != nil {
		c.logger.Warn("querying reboot-required state failed", "err", rebootErr)
	}

	c.mu.Lock()
	c.snap.refreshed = true
	c.snap.duration = c.now().Sub(start).Seconds()
	c.snap.updates = updates
	c.snap.reboot = reboot
	c.snap.ok = updates != nil
	if updates != nil {
		c.snap.lastSuccess = float64(c.now().Unix())
	}
	c.mu.Unlock()

	if updates != nil {
		c.maybeLogUpdates(updates)
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.updatesPending
	ch <- c.downloadBytes
	ch <- c.rebootRequired
	ch <- c.lastSuccess
	ch <- c.queryDuration
}

// Collect implements prometheus.Collector. It serves the cached snapshot and
// must never panic: before the first refresh, or after a failed one, it
// degrades to ubuntu_pro_up 0 with the detail metrics absent.
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

// maybeLogUpdates logs the full pending-update list when it changes, giving
// operators the per-package detail that would be too high-cardinality as
// labeled metrics.
func (c *Collector) maybeLogUpdates(pu *proclient.PackageUpdates) {
	if !c.logPackages {
		return
	}

	lines := make([]string, 0, len(pu.Updates))
	for _, u := range pu.Updates {
		lines = append(lines, fmt.Sprintf("%s %s %s %s", u.Package, u.Version, u.ProvidedBy, u.Status))
	}
	sort.Strings(lines)
	fingerprint := sha256.Sum256([]byte(strings.Join(lines, "\n")))

	c.mu.Lock()
	changed := fingerprint != c.loggedUpdates
	if changed {
		c.loggedUpdates = fingerprint
	}
	c.mu.Unlock()
	if !changed {
		return
	}

	c.logger.Info("pending package updates changed",
		"num_updates", len(pu.Updates),
		"updates", pu.Updates)
}
