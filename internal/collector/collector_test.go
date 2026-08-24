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
	updates   *proclient.PackageUpdates
	reboot    *proclient.RebootRequired
	installed *proclient.InstalledSummary
	cveData   *proclient.CVEData
	cvesErr   error
	manifest  []proclient.InstalledPackage
	attached  *bool
	version   string
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

func (f *fakeClient) InstalledSummary(context.Context) (*proclient.InstalledSummary, error) {
	if f.installed == nil {
		return nil, errors.New("pro exploded")
	}
	return f.installed, nil
}

func (f *fakeClient) PackageManifest(context.Context) ([]proclient.InstalledPackage, error) {
	if f.manifest == nil {
		return nil, errors.New("pro exploded")
	}
	return f.manifest, nil
}

func (f *fakeClient) CVEs(context.Context) (*proclient.CVEData, error) {
	if f.cvesErr != nil {
		return nil, f.cvesErr
	}
	if f.cveData == nil {
		return nil, errors.New("pro exploded")
	}
	return f.cveData, nil
}

func (f *fakeClient) IsAttached(context.Context) (bool, error) {
	if f.attached == nil {
		return false, errors.New("pro exploded")
	}
	return *f.attached, nil
}

func (f *fakeClient) ClientVersion(context.Context) (string, error) {
	if f.version == "" {
		return "", errors.New("pro exploded")
	}
	return f.version, nil
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

func testCVEData() *proclient.CVEData {
	return &proclient.CVEData{
		CVEs: map[string]proclient.CVEInfo{
			"CVE-2024-0001": {Priority: "critical"},
			"CVE-2024-0002": {Priority: "medium"},
			"CVE-2024-0003": {Priority: "low"},
		},
		Packages: map[string]proclient.CVEPackage{
			"libexample": {
				CurrentVersion: "1.0-1",
				CVEs: []proclient.CVEFix{
					{Name: "CVE-2024-0001", FixVersion: "1.0-1ubuntu0.1", FixStatus: "fixed", FixOrigin: "security"},
					{Name: "CVE-2024-0003", FixStatus: "vulnerable"},
				},
			},
			"othertool": {
				CurrentVersion: "2.4-2",
				CVEs: []proclient.CVEFix{
					{Name: "CVE-2024-0002", FixVersion: "2.4-2ubuntu0.1~esm1", FixStatus: "fixed", FixOrigin: "esm-apps"},
					{Name: "CVE-2024-0001", FixStatus: "vulnerable"},
				},
			},
		},
	}
}

func healthyFake() *fakeClient {
	attached := false
	return &fakeClient{
		updates: testUpdates(),
		reboot:  &proclient.RebootRequired{RebootRequired: "no"},
		installed: &proclient.InstalledSummary{
			NumInstalledPackages:  100,
			NumMainPackages:       80,
			NumUniversePackages:   12,
			NumThirdPartyPackages: 2,
			NumUnknownPackages:    6,
		},
		cveData:  testCVEData(),
		manifest: []proclient.InstalledPackage{{Package: "libexample", Version: "1.0-1"}},
		attached: &attached,
		version:  "37.2ubuntu~22.04.1",
	}
}

// newTestCollector fixes the clock so timestamps and durations are
// deterministic. Tests call Refresh explicitly instead of running the
// background loop.
func newTestCollector(client proclient.Client) *Collector {
	c := New(client, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{CollectCVEs: true})
	c.now = func() time.Time { return time.Unix(1700000000, 0) }
	return c
}

const allFamiliesAbsentExceptUp = `
# HELP ubuntu_pro_updates_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_up gauge
ubuntu_pro_updates_up 0
`

var allFamilyNames = []string{
	"ubuntu_pro_updates_up",
	"ubuntu_pro_updates_pending",
	"ubuntu_pro_updates_download_bytes",
	"ubuntu_pro_updates_reboot_required",
	"ubuntu_pro_updates_installed_packages",
	"ubuntu_pro_updates_cves",
	"ubuntu_pro_updates_cve_fixes",
	"ubuntu_pro_updates_attached",
	"ubuntu_pro_updates_client_info",
	"ubuntu_pro_updates_last_success_timestamp_seconds",
	"ubuntu_pro_updates_query_duration_seconds",
}

func TestCollectBeforeFirstRefresh(t *testing.T) {
	c := newTestCollector(healthyFake())

	// No Refresh has run: only up 0 may be exported, not even a duration.
	err := testutil.CollectAndCompare(c, strings.NewReader(allFamiliesAbsentExceptUp), allFamilyNames...)
	if err != nil {
		t.Error(err)
	}
}

func TestCollectSuccess(t *testing.T) {
	c := newTestCollector(healthyFake())
	c.Refresh(context.Background())

	expected := `
# HELP ubuntu_pro_updates_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_up gauge
ubuntu_pro_updates_up 1
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
# HELP ubuntu_pro_updates_installed_packages Number of installed packages, by archive origin.
# TYPE ubuntu_pro_updates_installed_packages gauge
ubuntu_pro_updates_installed_packages{origin="esm-apps"} 0
ubuntu_pro_updates_installed_packages{origin="esm-infra"} 0
ubuntu_pro_updates_installed_packages{origin="main"} 80
ubuntu_pro_updates_installed_packages{origin="multiverse"} 0
ubuntu_pro_updates_installed_packages{origin="restricted"} 0
ubuntu_pro_updates_installed_packages{origin="third-party"} 2
ubuntu_pro_updates_installed_packages{origin="universe"} 12
ubuntu_pro_updates_installed_packages{origin="unknown"} 6
# HELP ubuntu_pro_updates_cves Number of distinct CVEs affecting installed packages, by priority and fix status. A CVE counts as fixed when a fix exists for at least one of its affected packages; absent on pro clients older than 35.
# TYPE ubuntu_pro_updates_cves gauge
ubuntu_pro_updates_cves{fix_status="fixed",priority="critical"} 1
ubuntu_pro_updates_cves{fix_status="fixed",priority="high"} 0
ubuntu_pro_updates_cves{fix_status="fixed",priority="low"} 0
ubuntu_pro_updates_cves{fix_status="fixed",priority="medium"} 1
ubuntu_pro_updates_cves{fix_status="fixed",priority="negligible"} 0
ubuntu_pro_updates_cves{fix_status="unknown",priority="critical"} 0
ubuntu_pro_updates_cves{fix_status="unknown",priority="high"} 0
ubuntu_pro_updates_cves{fix_status="unknown",priority="low"} 0
ubuntu_pro_updates_cves{fix_status="unknown",priority="medium"} 0
ubuntu_pro_updates_cves{fix_status="unknown",priority="negligible"} 0
ubuntu_pro_updates_cves{fix_status="vulnerable",priority="critical"} 0
ubuntu_pro_updates_cves{fix_status="vulnerable",priority="high"} 0
ubuntu_pro_updates_cves{fix_status="vulnerable",priority="low"} 1
ubuntu_pro_updates_cves{fix_status="vulnerable",priority="medium"} 0
ubuntu_pro_updates_cves{fix_status="vulnerable",priority="negligible"} 0
# HELP ubuntu_pro_updates_cve_fixes Number of package-CVE pairs with a released fix this host has not applied, by the pocket the fix comes from; esm pockets need an Ubuntu Pro subscription. Absent on pro clients older than 35.
# TYPE ubuntu_pro_updates_cve_fixes gauge
ubuntu_pro_updates_cve_fixes{origin="esm-apps"} 1
ubuntu_pro_updates_cve_fixes{origin="esm-infra"} 0
ubuntu_pro_updates_cve_fixes{origin="security"} 1
ubuntu_pro_updates_cve_fixes{origin="updates"} 0
# HELP ubuntu_pro_updates_attached Whether the host is attached to an Ubuntu Pro subscription.
# TYPE ubuntu_pro_updates_attached gauge
ubuntu_pro_updates_attached 0
# HELP ubuntu_pro_updates_client_info Installed Ubuntu Pro client version. CVE metrics need version 35 or newer.
# TYPE ubuntu_pro_updates_client_info gauge
ubuntu_pro_updates_client_info{version="37.2ubuntu~22.04.1"} 1
# HELP ubuntu_pro_updates_last_success_timestamp_seconds Unix time of the last successful package-updates refresh; absent until one succeeds.
# TYPE ubuntu_pro_updates_last_success_timestamp_seconds gauge
ubuntu_pro_updates_last_success_timestamp_seconds 1.7e+09
`
	err := testutil.CollectAndCompare(c, strings.NewReader(expected), allFamilyNames[:len(allFamilyNames)-1]...)
	if err != nil {
		t.Error(err)
	}
}

func TestCollectProFailure(t *testing.T) {
	c := newTestCollector(&fakeClient{})
	c.Refresh(context.Background())

	// Every query failed: up 0 and a duration; detail families and the
	// never-succeeded timestamp must be absent.
	expected := `
# HELP ubuntu_pro_updates_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_up gauge
ubuntu_pro_updates_up 0
# HELP ubuntu_pro_updates_query_duration_seconds Time spent querying the Ubuntu Pro client during the last refresh.
# TYPE ubuntu_pro_updates_query_duration_seconds gauge
ubuntu_pro_updates_query_duration_seconds 0
`
	err := testutil.CollectAndCompare(c, strings.NewReader(expected), allFamilyNames...)
	if err != nil {
		t.Error(err)
	}
}

func TestCVEUnsupportedClient(t *testing.T) {
	fake := healthyFake()
	fake.cvesErr = &proclient.APIError{Code: "api-invalid-endpoint", Title: "'u.pro.security.cves.v1' is not a valid endpoint"}
	c := newTestCollector(fake)
	c.Refresh(context.Background())

	// The rest of the collection stays healthy; only the CVE families are
	// absent until the pro client is upgraded.
	if got := testutil.CollectAndCount(c, "ubuntu_pro_updates_cves", "ubuntu_pro_updates_cve_fixes"); got != 0 {
		t.Errorf("cve series with unsupported client = %d, want 0", got)
	}
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ubuntu_pro_updates_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_up gauge
ubuntu_pro_updates_up 1
`), "ubuntu_pro_updates_up"); err != nil {
		t.Error(err)
	}
}

func TestCVEsDisabledByOption(t *testing.T) {
	c := New(healthyFake(), slog.New(slog.NewTextHandler(io.Discard, nil)), Options{CollectCVEs: false})
	c.now = func() time.Time { return time.Unix(1700000000, 0) }
	c.Refresh(context.Background())

	if got := testutil.CollectAndCount(c, "ubuntu_pro_updates_cves", "ubuntu_pro_updates_cve_fixes"); got != 0 {
		t.Errorf("cve series with collection disabled = %d, want 0", got)
	}
}

func TestLastSuccessSurvivesFailedRefresh(t *testing.T) {
	fake := healthyFake()
	c := newTestCollector(fake)
	c.Refresh(context.Background())

	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ubuntu_pro_updates_last_success_timestamp_seconds Unix time of the last successful package-updates refresh; absent until one succeeds.
# TYPE ubuntu_pro_updates_last_success_timestamp_seconds gauge
ubuntu_pro_updates_last_success_timestamp_seconds 1.7e+09
`), "ubuntu_pro_updates_last_success_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}

	// The pro client starts failing; the timestamp of the last success must
	// keep being exported so staleness can be alerted on, while the stale
	// detail metrics are dropped rather than served as fresh.
	fake.updates = nil
	c.Refresh(context.Background())
	if err := testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ubuntu_pro_updates_up Whether the last refresh of package updates from the Ubuntu Pro client succeeded.
# TYPE ubuntu_pro_updates_up gauge
ubuntu_pro_updates_up 0
# HELP ubuntu_pro_updates_last_success_timestamp_seconds Unix time of the last successful package-updates refresh; absent until one succeeds.
# TYPE ubuntu_pro_updates_last_success_timestamp_seconds gauge
ubuntu_pro_updates_last_success_timestamp_seconds 1.7e+09
`), "ubuntu_pro_updates_up", "ubuntu_pro_updates_last_success_timestamp_seconds", "ubuntu_pro_updates_pending"); err != nil {
		t.Error(err)
	}
}

func TestUnknownPocketAndStatusGetSeries(t *testing.T) {
	fake := healthyFake()
	fake.updates = &proclient.PackageUpdates{
		Summary: proclient.Summary{NumUpdates: 1},
		Updates: []proclient.Update{
			{Package: "mystery", Version: "1.0", DownloadSize: 10, ProvidedBy: "esm-shiny", Status: "brand_new_status"},
		},
	}
	c := newTestCollector(fake)
	c.Refresh(context.Background())

	got := testutil.CollectAndCount(c, "ubuntu_pro_updates_pending")
	// 4 known pockets x 5 known statuses, plus the unknown combination.
	if got != 21 {
		t.Errorf("series count = %d, want 21", got)
	}
}

func TestCollectorLint(t *testing.T) {
	c := newTestCollector(healthyFake())
	c.Refresh(context.Background())

	problems, err := testutil.CollectAndLint(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("lint: %s: %s", p.Metric, p.Text)
	}
}
