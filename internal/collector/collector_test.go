package collector

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/basecamp/ubuntu_pro_updates_exporter/internal/proclient"
)

// fakeClient serves canned responses; a nil field means that call errors.
type fakeClient struct {
	updates *proclient.PackageUpdates
	reboot  *proclient.RebootRequired
}

func (f *fakeClient) PackageUpdates(context.Context) (*proclient.PackageUpdates, error) {
	if f.updates == nil {
		return nil, errors.New("pro exploded")
	}
	return f.updates, nil
}

func (f *fakeClient) RebootRequired(context.Context) (*proclient.RebootRequired, error) {
	if f.reboot == nil {
		return nil, errors.New("pro exploded")
	}
	return f.reboot, nil
}

func testUpdates() *proclient.PackageUpdates {
	return &proclient.PackageUpdates{
		Summary: proclient.Summary{
			NumUpdates:                 4,
			NumESMAppsUpdates:          1,
			NumESMInfraUpdates:         0,
			NumStandardSecurityUpdates: 2,
			NumStandardUpdates:         1,
		},
		Updates: []proclient.Update{
			{Package: "openssl", Version: "3.0.2-0ubuntu1.18", DownloadSize: 100, Origin: "archive.ubuntu.com", ProvidedBy: "standard-security", Status: "upgrade_available"},
			{Package: "curl", Version: "7.81.0-1ubuntu1.20", DownloadSize: 50, Origin: "archive.ubuntu.com", ProvidedBy: "standard-security", Status: "upgrade_available"},
			{Package: "imagemagick", Version: "8:6.9.11+esm1", DownloadSize: 200, Origin: "esm.ubuntu.com", ProvidedBy: "esm-apps", Status: "pending_attach"},
			{Package: "tzdata", Version: "2024a-0ubuntu0.22.04.1", DownloadSize: 25, Origin: "archive.ubuntu.com", ProvidedBy: "standard-updates", Status: "upgrade_available_not_preferred"},
		},
	}
}

// newTestCollector fixes the clock so timestamps and durations are
// deterministic. Tests call Refresh explicitly instead of running the
// background loop.
func newTestCollector(client proclient.Client) *Collector {
	c := New(client, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	c.now = func() time.Time { return time.Unix(1700000000, 0) }
	return c
}

const allFamiliesAbsentExceptUp = `
# HELP ubuntu_pro_updates_exporter_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_exporter_up gauge
ubuntu_pro_updates_exporter_up 0
`

var allFamilyNames = []string{
	"ubuntu_pro_updates_exporter_up",
	"ubuntu_pro_updates_pending",
	"ubuntu_pro_updates_download_bytes",
	"ubuntu_pro_updates_reboot_required",
	"ubuntu_pro_updates_exporter_last_success_timestamp_seconds",
	"ubuntu_pro_updates_exporter_query_duration_seconds",
}

func TestCollectBeforeFirstRefresh(t *testing.T) {
	c := newTestCollector(&fakeClient{updates: testUpdates(), reboot: &proclient.RebootRequired{RebootRequired: "no"}})

	// No Refresh has run: only up 0 may be exported, not even a duration.
	err := testutil.CollectAndCompare(c, strings.NewReader(allFamiliesAbsentExceptUp), allFamilyNames...)
	if err != nil {
		t.Error(err)
	}
}

func TestCollectSuccess(t *testing.T) {
	c := newTestCollector(&fakeClient{updates: testUpdates(), reboot: &proclient.RebootRequired{RebootRequired: "no"}})
	c.Refresh(context.Background())

	expected := `
# HELP ubuntu_pro_updates_exporter_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_exporter_up gauge
ubuntu_pro_updates_exporter_up 1
# HELP ubuntu_pro_updates_pending Number of pending package updates, by pocket and update status.
# TYPE ubuntu_pro_updates_pending gauge
ubuntu_pro_updates_pending{pocket="esm-apps",status="pending_attach"} 1
ubuntu_pro_updates_pending{pocket="esm-apps",status="pending_enable"} 0
ubuntu_pro_updates_pending{pocket="esm-apps",status="upgrade_available"} 0
ubuntu_pro_updates_pending{pocket="esm-apps",status="upgrade_available_not_preferred"} 0
ubuntu_pro_updates_pending{pocket="esm-apps",status="upgrade_unavailable"} 0
ubuntu_pro_updates_pending{pocket="esm-infra",status="pending_attach"} 0
ubuntu_pro_updates_pending{pocket="esm-infra",status="pending_enable"} 0
ubuntu_pro_updates_pending{pocket="esm-infra",status="upgrade_available"} 0
ubuntu_pro_updates_pending{pocket="esm-infra",status="upgrade_available_not_preferred"} 0
ubuntu_pro_updates_pending{pocket="esm-infra",status="upgrade_unavailable"} 0
ubuntu_pro_updates_pending{pocket="standard-security",status="pending_attach"} 0
ubuntu_pro_updates_pending{pocket="standard-security",status="pending_enable"} 0
ubuntu_pro_updates_pending{pocket="standard-security",status="upgrade_available"} 2
ubuntu_pro_updates_pending{pocket="standard-security",status="upgrade_available_not_preferred"} 0
ubuntu_pro_updates_pending{pocket="standard-security",status="upgrade_unavailable"} 0
ubuntu_pro_updates_pending{pocket="standard-updates",status="pending_attach"} 0
ubuntu_pro_updates_pending{pocket="standard-updates",status="pending_enable"} 0
ubuntu_pro_updates_pending{pocket="standard-updates",status="upgrade_available"} 0
ubuntu_pro_updates_pending{pocket="standard-updates",status="upgrade_available_not_preferred"} 1
ubuntu_pro_updates_pending{pocket="standard-updates",status="upgrade_unavailable"} 0
# HELP ubuntu_pro_updates_download_bytes Total download size of pending package updates, by pocket.
# TYPE ubuntu_pro_updates_download_bytes gauge
ubuntu_pro_updates_download_bytes{pocket="esm-apps"} 200
ubuntu_pro_updates_download_bytes{pocket="esm-infra"} 0
ubuntu_pro_updates_download_bytes{pocket="standard-security"} 150
ubuntu_pro_updates_download_bytes{pocket="standard-updates"} 25
# HELP ubuntu_pro_updates_reboot_required Reboot-required state of the host; the active state has value 1. State yes-kernel-livepatches-applied means a reboot is pending but Livepatch covers the running kernel.
# TYPE ubuntu_pro_updates_reboot_required gauge
ubuntu_pro_updates_reboot_required{state="no"} 1
ubuntu_pro_updates_reboot_required{state="yes"} 0
ubuntu_pro_updates_reboot_required{state="yes-kernel-livepatches-applied"} 0
# HELP ubuntu_pro_updates_exporter_last_success_timestamp_seconds Unix time of the last successful package-updates refresh; absent until one succeeds.
# TYPE ubuntu_pro_updates_exporter_last_success_timestamp_seconds gauge
ubuntu_pro_updates_exporter_last_success_timestamp_seconds 1.7e+09
# HELP ubuntu_pro_updates_exporter_query_duration_seconds Time spent querying the Ubuntu Pro client during the last refresh.
# TYPE ubuntu_pro_updates_exporter_query_duration_seconds gauge
ubuntu_pro_updates_exporter_query_duration_seconds 0
`
	err := testutil.CollectAndCompare(c, strings.NewReader(expected), allFamilyNames...)
	if err != nil {
		t.Error(err)
	}
}

func TestCollectProFailure(t *testing.T) {
	c := newTestCollector(&fakeClient{})
	c.Refresh(context.Background())

	// Both queries failed: up 0 and a duration; detail families and the
	// never-succeeded timestamp must be absent.
	expected := `
# HELP ubuntu_pro_updates_exporter_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_exporter_up gauge
ubuntu_pro_updates_exporter_up 0
# HELP ubuntu_pro_updates_exporter_query_duration_seconds Time spent querying the Ubuntu Pro client during the last refresh.
# TYPE ubuntu_pro_updates_exporter_query_duration_seconds gauge
ubuntu_pro_updates_exporter_query_duration_seconds 0
`
	err := testutil.CollectAndCompare(c, strings.NewReader(expected), allFamilyNames...)
	if err != nil {
		t.Error(err)
	}
}

func TestLastSuccessSurvivesFailedRefresh(t *testing.T) {
	fake := &fakeClient{updates: testUpdates(), reboot: &proclient.RebootRequired{RebootRequired: "no"}}
	c := newTestCollector(fake)
	c.Refresh(context.Background())

	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ubuntu_pro_updates_exporter_last_success_timestamp_seconds Unix time of the last successful package-updates refresh; absent until one succeeds.
# TYPE ubuntu_pro_updates_exporter_last_success_timestamp_seconds gauge
ubuntu_pro_updates_exporter_last_success_timestamp_seconds 1.7e+09
`), "ubuntu_pro_updates_exporter_last_success_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}

	// The pro client starts failing; the timestamp of the last success must
	// keep being exported so staleness can be alerted on, while the stale
	// detail metrics are dropped rather than served as fresh.
	fake.updates = nil
	c.Refresh(context.Background())
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ubuntu_pro_updates_exporter_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_exporter_up gauge
ubuntu_pro_updates_exporter_up 0
# HELP ubuntu_pro_updates_exporter_last_success_timestamp_seconds Unix time of the last successful package-updates refresh; absent until one succeeds.
# TYPE ubuntu_pro_updates_exporter_last_success_timestamp_seconds gauge
ubuntu_pro_updates_exporter_last_success_timestamp_seconds 1.7e+09
`), "ubuntu_pro_updates_exporter_up", "ubuntu_pro_updates_exporter_last_success_timestamp_seconds", "ubuntu_pro_updates_pending"); err != nil {
		t.Error(err)
	}
}

func TestUnknownPocketAndStatusGetSeries(t *testing.T) {
	pu := &proclient.PackageUpdates{
		Summary: proclient.Summary{NumUpdates: 1},
		Updates: []proclient.Update{
			{Package: "mystery", Version: "1.0", DownloadSize: 10, ProvidedBy: "esm-shiny", Status: "brand_new_status"},
		},
	}
	c := newTestCollector(&fakeClient{updates: pu, reboot: &proclient.RebootRequired{RebootRequired: "no"}})
	c.Refresh(context.Background())

	got := testutil.CollectAndCount(c, "ubuntu_pro_updates_pending")
	// 4 known pockets x 5 known statuses, plus the unknown combination.
	if got != 21 {
		t.Errorf("series count = %d, want 21", got)
	}
}

func TestCollectorLint(t *testing.T) {
	c := newTestCollector(&fakeClient{updates: testUpdates(), reboot: &proclient.RebootRequired{RebootRequired: "no"}})
	c.Refresh(context.Background())

	problems, err := testutil.CollectAndLint(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("lint: %s: %s", p.Metric, p.Text)
	}
}
