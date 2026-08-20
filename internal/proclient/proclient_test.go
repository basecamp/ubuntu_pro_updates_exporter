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
