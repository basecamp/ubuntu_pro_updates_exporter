package proclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubClient returns an ExecClient whose process execution is replaced by a
// canned result.
func stubClient(t *testing.T, stdout, stderr []byte, err error) *ExecClient {
	t.Helper()
	c := NewExecClient("pro", time.Second)
	c.run = func(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
		if name != "pro" || len(args) != 2 || args[0] != "api" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return stdout, stderr, err
	}
	return c
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}
	return b
}

func TestPackageUpdatesSuccess(t *testing.T) {
	// The testdata file carries a realistic response shape for an unattached
	// host, with a truncated, representative updates array.
	c := stubClient(t, readTestdata(t, "updates_success.json"), nil, nil)

	pu, err := c.PackageUpdates(context.Background())
	if err != nil {
		t.Fatalf("PackageUpdates: %v", err)
	}

	want := Summary{
		NumUpdates:                 85,
		NumESMAppsUpdates:          5,
		NumESMInfraUpdates:         0,
		NumStandardSecurityUpdates: 57,
		NumStandardUpdates:         23,
	}
	if pu.Summary != want {
		t.Errorf("summary = %+v, want %+v", pu.Summary, want)
	}

	if len(pu.Updates) != 5 {
		t.Fatalf("len(updates) = %d, want 5", len(pu.Updates))
	}
	first := Update{
		Package:      "distro-info-data",
		Version:      "0.52ubuntu0.9+esm1",
		DownloadSize: 516096,
		Origin:       "esm.ubuntu.com",
		ProvidedBy:   "esm-apps",
		Status:       "pending_attach",
	}
	if pu.Updates[0] != first {
		t.Errorf("updates[0] = %+v, want %+v", pu.Updates[0], first)
	}
}

func TestPackageUpdatesFailureEnvelope(t *testing.T) {
	// pro exits 1 on failure but still prints a JSON envelope; the envelope
	// must win over the exit code.
	c := stubClient(t, readTestdata(t, "updates_failure.json"), nil, errors.New("exit status 1"))

	_, err := c.PackageUpdates(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Code != "api-invalid-endpoint" {
		t.Errorf("code = %q, want %q", apiErr.Code, "api-invalid-endpoint")
	}
}

func TestPackageUpdatesNoJSON(t *testing.T) {
	// A pro client too old for `pro api` prints a usage error on stderr and
	// nothing useful on stdout.
	c := stubClient(t, nil, []byte("usage: pro <command>\npro: error: argument"), errors.New("exit status 2"))

	_, err := c.PackageUpdates(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "usage: pro <command>") {
		t.Errorf("error should carry the first stderr line, got: %v", err)
	}
}

func TestPackageUpdatesGarbageWithZeroExit(t *testing.T) {
	c := stubClient(t, []byte("not json"), nil, nil)

	_, err := c.PackageUpdates(context.Background())
	if err == nil || !strings.Contains(err.Error(), "parsing envelope") {
		t.Errorf("expected envelope parse error, got: %v", err)
	}
}

func TestPackageUpdatesMissingAttributes(t *testing.T) {
	c := stubClient(t, []byte(`{"result": "success", "data": {"meta": {}}}`), nil, nil)

	_, err := c.PackageUpdates(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no data.attributes") {
		t.Errorf("expected missing-attributes error, got: %v", err)
	}
}

func TestInstalledSummary(t *testing.T) {
	c := stubClient(t, readTestdata(t, "summary_success.json"), nil, nil)

	s, err := c.InstalledSummary(context.Background())
	if err != nil {
		t.Fatalf("InstalledSummary: %v", err)
	}

	want := InstalledSummary{
		NumInstalledPackages:  100,
		NumMainPackages:       80,
		NumUniversePackages:   12,
		NumThirdPartyPackages: 2,
		NumUnknownPackages:    6,
	}
	if *s != want {
		t.Errorf("summary = %+v, want %+v", *s, want)
	}
}

func TestPackageManifest(t *testing.T) {
	c := stubClient(t, readTestdata(t, "manifest_success.json"), nil, nil)

	packages, err := c.PackageManifest(context.Background())
	if err != nil {
		t.Fatalf("PackageManifest: %v", err)
	}

	want := []InstalledPackage{
		{Package: "libexample", Version: "1.0-1"},
		{Package: "othertool:amd64", Version: "2.4-2"},
		{Package: "widgetd", Version: "0.3-2"},
	}
	if len(packages) != len(want) {
		t.Fatalf("len(packages) = %d, want %d", len(packages), len(want))
	}
	for i := range want {
		if packages[i] != want[i] {
			t.Errorf("packages[%d] = %+v, want %+v", i, packages[i], want[i])
		}
	}
}

func TestCVEs(t *testing.T) {
	c := stubClient(t, readTestdata(t, "cves_success.json"), nil, nil)

	data, err := c.CVEs(context.Background())
	if err != nil {
		t.Fatalf("CVEs: %v", err)
	}

	if len(data.CVEs) != 3 || len(data.Packages) != 2 {
		t.Fatalf("got %d cves and %d packages, want 3 and 2", len(data.CVEs), len(data.Packages))
	}
	if data.CVEs["CVE-2024-0001"].Priority != "critical" {
		t.Errorf("CVE-2024-0001 priority = %q, want critical", data.CVEs["CVE-2024-0001"].Priority)
	}
	if score := data.CVEs["CVE-2024-0001"].CVSSScore; score == nil || *score != 9.8 {
		t.Errorf("CVE-2024-0001 cvss_score = %v, want 9.8", score)
	}
	if severity := data.CVEs["CVE-2024-0001"].CVSSSeverity; severity != "critical" {
		t.Errorf("CVE-2024-0001 cvss_severity = %q, want critical", severity)
	}
	fix := data.Packages["libexample"].CVEs[0]
	want := CVEFix{Name: "CVE-2024-0001", FixVersion: "1.0-1ubuntu0.1", FixStatus: "fixed", FixOrigin: "security"}
	if fix != want {
		t.Errorf("libexample fix = %+v, want %+v", fix, want)
	}
	// null fix_origin/fix_version decode to empty strings
	unfixed := data.Packages["libexample"].CVEs[1]
	if unfixed.FixStatus != "vulnerable" || unfixed.FixOrigin != "" || unfixed.FixVersion != "" {
		t.Errorf("unfixed pair = %+v, want vulnerable with empty fix fields", unfixed)
	}
}

func TestIsAttachedAndVersion(t *testing.T) {
	c := stubClient(t, []byte(`{"result": "success", "data": {"attributes": {"is_attached": false, "contract_status": null}}}`), nil, nil)
	attached, err := c.IsAttached(context.Background())
	if err != nil || attached {
		t.Errorf("IsAttached = %v, %v; want false, nil", attached, err)
	}

	c = stubClient(t, []byte(`{"result": "success", "data": {"attributes": {"installed_version": "37.2ubuntu~22.04.1"}}}`), nil, nil)
	version, err := c.ClientVersion(context.Background())
	if err != nil || version != "37.2ubuntu~22.04.1" {
		t.Errorf("ClientVersion = %q, %v; want 37.2ubuntu~22.04.1, nil", version, err)
	}
}

func TestIsUnsupported(t *testing.T) {
	// An old client rejects the endpoint name inside a failure envelope.
	c := stubClient(t, []byte(`{"result": "failure", "errors": [{"code": "api-invalid-endpoint", "title": "'u.pro.security.cves.v1' is not a valid endpoint"}]}`), nil, errors.New("exit status 1"))
	_, err := c.CVEs(context.Background())
	if !IsUnsupported(err) {
		t.Errorf("IsUnsupported(%v) = false, want true", err)
	}

	if IsUnsupported(errors.New("some other failure")) {
		t.Error("IsUnsupported(plain error) = true, want false")
	}
}

func TestRebootRequired(t *testing.T) {
	c := stubClient(t, readTestdata(t, "reboot_required.json"), nil, nil)

	rr, err := c.RebootRequired(context.Background())
	if err != nil {
		t.Fatalf("RebootRequired: %v", err)
	}
	if rr.RebootRequired != "yes" {
		t.Errorf("reboot_required = %q, want %q", rr.RebootRequired, "yes")
	}
}
