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
		proTimeout = flag.Duration("pro.timeout", 30*time.Second,
			"Timeout for a single pro api invocation.")
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
			"Log the fixable package-CVE pairs whenever they change.")
		logCVEsInEffect = flag.Bool("log.cves-in-effect", false,
			"Also log the in-effect package-CVE pairs (no fix released yet) whenever they change, "+
				"at or above log.cves-min-priority, so operators can mitigate in the meantime.")
		logCVEsMinPriority = flag.String("log.cves-min-priority", "high",
			"Minimum Ubuntu CVE priority for the in-effect CVE log: negligible, low, medium, high or critical.")
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

	switch *logCVEsMinPriority {
	case "negligible", "low", "medium", "high", "critical":
	default:
		fmt.Fprintf(os.Stderr, "unknown log.cves-min-priority %q (want negligible, low, medium, high or critical)\n", *logCVEsMinPriority)
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
		LogCVEsInEffect:      *logCVEsInEffect,
		LogCVEsMinPriority:   *logCVEsMinPriority,
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
