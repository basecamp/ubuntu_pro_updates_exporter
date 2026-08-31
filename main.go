// Command ubuntu-pro-updates-exporter is a Prometheus exporter for Ubuntu
// package-update status, sourced from the Ubuntu Pro client's
// machine-readable API (`pro api u.pro.packages.updates.v1`).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/basecamp/ubuntu_pro_updates_exporter/internal/collector"
	"github.com/basecamp/ubuntu_pro_updates_exporter/internal/proclient"
)

// Build-time variables, injected via -ldflags (see Makefile and
// .goreleaser.yaml).
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		listenAddress = flag.String("web.listen-address", ":10052",
			"Address on which to expose metrics.")
		metricsPath = flag.String("web.telemetry-path", "/metrics",
			"Path under which to expose metrics.")
		proBinary = flag.String("pro.binary", "pro",
			"Ubuntu Pro client executable, resolved via $PATH unless it contains a slash.")
		proTimeout = flag.Duration("pro.timeout", 10*time.Minute,
			"Timeout for a single pro api invocation. The default is sized for pro client 37, "+
				"whose updates query costs roughly 0.6s of CPU per pending update on top of a "+
				"few seconds of base work; the refresh runs in the background, so a long call "+
				"never delays a scrape.")
		refreshInterval = flag.Duration("pro.refresh-interval", 12*time.Hour,
			"How often to refresh update data from the pro client; scrapes serve the cached result. "+
				"The default matches apt-daily's own cadence (twice a day, refreshing lists at most "+
				"once per day), since the data only changes when apt metadata is refreshed or "+
				"packages are installed.")
		logFormat = flag.String("log.format", "text",
			"Log format: text or json.")
		collectCVEs = flag.Bool("pro.cves", true,
			"Collect CVE metrics via u.pro.security.cves.v1. Needs pro client 35 or newer and "+
				"network access; on an older client the exporter warns once and disables CVE "+
				"collection. Restart the exporter after upgrading the client.")
		logPackages = flag.Bool("log.package-updates", false,
			"Log the full list of pending package updates whenever it changes.")
		logInstalled = flag.Bool("log.installed-packages", false,
			"Log the installed-package manifest whenever it changes.")
		logCVEs = flag.Bool("log.cves", false,
			"Log the package-CVE pairs affecting installed packages whenever they change; "+
				"shaped by log.cves-statuses and log.cves-priorities.")
		logCVEsStatuses = flag.String("log.cves-statuses", "fixed,vulnerable,unknown",
			"Fix statuses the CVE log includes, comma separated: fixed (a fix exists the host "+
				"has not applied), vulnerable (no fix released) and unknown (fix availability "+
				"undetermined).")
		logCVEsPriorities = flag.String("log.cves-priorities", "high,critical",
			"Ubuntu CVE priorities the CVE log includes, comma separated: "+
				"negligible, low, medium, high, critical.")
		logSnapshotInterval = flag.Duration("log.snapshot-interval", 24*time.Hour,
			"Re-log an unchanged list as a fresh snapshot once its last snapshot is this old, "+
				"so a log store with retention always holds the current list; a dashboard "+
				"then only needs to look back this far. 0 logs on change only.")
		printVersion = flag.Bool("version", false,
			"Print version and exit.")
	)
	flag.Parse()

	if *printVersion {
		fmt.Printf("ubuntu-pro-updates-exporter %s (commit %s, built %s, %s)\n",
			version, commit, date, runtime.Version())
		return 0
	}

	logger, err := newLogger(*logFormat)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	cveStatuses, err := parseListFlag("log.cves-statuses", *logCVEsStatuses,
		"fixed", "vulnerable", "unknown")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cvePriorities, err := parseListFlag("log.cves-priorities", *logCVEsPriorities,
		"negligible", "low", "medium", "high", "critical")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if _, err := exec.LookPath(*proBinary); err != nil {
		// Not fatal: the exporter still serves ubuntu_pro_updates_exporter_up 0,
		// so a fleet-wide rollout can observe hosts lacking the pro client.
		logger.Warn("ubuntu pro client not found, ubuntu_pro_updates_exporter_up will be 0",
			"binary", *proBinary, "err", err)
	}

	client := proclient.NewExecClient(*proBinary, *proTimeout)
	col := collector.New(client, logger, collector.Options{
		CollectCVEs:          *collectCVEs,
		LogPackageUpdates:    *logPackages,
		LogInstalledPackages: *logInstalled,
		LogCVEs:              *logCVEs,
		LogCVEsStatuses:      cveStatuses,
		LogCVEsPriorities:    cvePriorities,
		LogSnapshotInterval:  *logSnapshotInterval,
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		newBuildInfo(),
		col,
	)

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}))
	if *metricsPath != "/" {
		landing := []byte(`<html><head><title>Ubuntu Pro Updates Exporter</title></head>
<body><h1>Ubuntu Pro Updates Exporter</h1><p><a href="` + *metricsPath + `">Metrics</a></p></body></html>`)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write(landing)
		})
	}

	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Refresh in the background so scrapes serve the cached snapshot
	// instantly instead of paying for a multi-second pro invocation.
	go col.Run(ctx, *refreshInterval)

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("listening", "version", version, "address", *listenAddress, "metrics_path", *metricsPath)

	select {
	case err := <-serveErr:
		logger.Error("http server failed", "err", err)
		return 1
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			logger.Error("shutdown failed", "err", err)
			return 1
		}
	}
	return 0
}

// parseListFlag splits a comma-separated flag value and rejects anything
// outside the allowed values. List flags are the exporter's standard filter
// shape: a boolean log.* flag enables a log, a list flag picks the values
// it includes.
func parseListFlag(name, value string, allowed ...string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	var values []string
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		ok := false
		for _, a := range allowed {
			if v == a {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("unknown %s value %q (want a comma-separated subset of %s)",
				name, v, strings.Join(allowed, ", "))
		}
		values = append(values, v)
	}
	return values, nil
}

func newLogger(format string) (*slog.Logger, error) {
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, nil)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, nil)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q (want text or json)", format)
	}
}

func newBuildInfo() prometheus.Collector {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ubuntu_pro_updates_exporter_build_info",
		Help: "Build information about the ubuntu-pro-updates-exporter.",
	}, []string{"version", "revision", "goversion"})
	g.WithLabelValues(version, commit, runtime.Version()).Set(1)
	return g
}
