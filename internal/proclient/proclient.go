// Package proclient invokes the Ubuntu Pro client's machine-readable API
// (`pro api <endpoint>`) and parses its JSON envelope.
//
// Both endpoints used here were introduced in Ubuntu Pro Client 27.12, work
// on unattached (free) hosts, require no root privileges and no network
// access: they read the local apt caches, so results are only as fresh as the
// last `apt update`.
package proclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	packageUpdatesEndpoint  = "u.pro.packages.updates.v1"
	rebootRequiredEndpoint  = "u.pro.security.status.reboot_required.v1"
	packageSummaryEndpoint  = "u.pro.packages.summary.v1"
	packageManifestEndpoint = "u.security.package_manifest.v1"
	cvesEndpoint            = "u.pro.security.cves.v1"
	isAttachedEndpoint      = "u.pro.status.is_attached.v1"
	versionEndpoint         = "u.pro.version.v1"
)

// Pockets lists every value the pro client emits as an update's provided_by
// field. Exposing the full set lets the collector publish stable zero-valued
// series.
var Pockets = []string{"standard-security", "standard-updates", "esm-apps", "esm-infra"}

// Statuses lists every value of an update's status field (the pro client's
// UpdateStatus enum).
var Statuses = []string{
	"upgrade_available",
	"upgrade_available_not_preferred",
	"pending_attach",
	"pending_enable",
	"upgrade_unavailable",
}

// RebootStates lists every value reboot_required can take.
var RebootStates = []string{"no", "yes", "yes-kernel-livepatches-applied"}

// PackageOrigins lists the origins the installed-package summary counts by.
var PackageOrigins = []string{
	"main",
	"universe",
	"multiverse",
	"restricted",
	"esm-apps",
	"esm-infra",
	"third-party",
	"unknown",
}

// CVEPriorities lists the Ubuntu CVE priority values.
var CVEPriorities = []string{"negligible", "low", "medium", "high", "critical"}

// CVEFixStatuses lists every value a package-CVE pair's fix_status can take.
var CVEFixStatuses = []string{"fixed", "vulnerable", "unknown"}

// FixOrigins lists the pockets a CVE fix can come from.
var FixOrigins = []string{"security", "updates", "esm-apps", "esm-infra"}

// Summary mirrors data.attributes.summary of u.pro.packages.updates.v1.
type Summary struct {
	NumUpdates                 int `json:"num_updates"`
	NumESMAppsUpdates          int `json:"num_esm_apps_updates"`
	NumESMInfraUpdates         int `json:"num_esm_infra_updates"`
	NumStandardSecurityUpdates int `json:"num_standard_security_updates"`
	NumStandardUpdates         int `json:"num_standard_updates"`
}

// Update mirrors one element of data.attributes.updates.
type Update struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	DownloadSize int64  `json:"download_size"`
	Origin       string `json:"origin"`
	ProvidedBy   string `json:"provided_by"`
	Status       string `json:"status"`
}

// PackageUpdates mirrors data.attributes of u.pro.packages.updates.v1.
type PackageUpdates struct {
	Summary Summary  `json:"summary"`
	Updates []Update `json:"updates"`
}

// RebootRequired mirrors the fields of u.pro.security.status.reboot_required.v1
// that the exporter consumes.
type RebootRequired struct {
	// RebootRequired is "no", "yes", or "yes-kernel-livepatches-applied"
	// (a reboot is pending but Livepatch covers the running kernel).
	RebootRequired string `json:"reboot_required"`
}

// InstalledSummary mirrors data.attributes.summary of u.pro.packages.summary.v1.
type InstalledSummary struct {
	NumInstalledPackages  int `json:"num_installed_packages"`
	NumMainPackages       int `json:"num_main_packages"`
	NumUniversePackages   int `json:"num_universe_packages"`
	NumMultiversePackages int `json:"num_multiverse_packages"`
	NumRestrictedPackages int `json:"num_restricted_packages"`
	NumESMAppsPackages    int `json:"num_esm_apps_packages"`
	NumESMInfraPackages   int `json:"num_esm_infra_packages"`
	NumThirdPartyPackages int `json:"num_third_party_packages"`
	NumUnknownPackages    int `json:"num_unknown_packages"`
}

// InstalledPackage is one entry of the u.security.package_manifest.v1 data,
// the manifest format Ubuntu's CVE tooling consumes. Package keeps the
// manifest's name verbatim, which may carry an architecture suffix
// (e.g. "othertool:amd64").
type InstalledPackage struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// CVEFix is one package-CVE pair from u.pro.security.cves.v1: whether and
// where a fix exists for this CVE in this package. FixVersion and FixOrigin
// are empty when no fix has been released (fix_status "vulnerable" or
// "unknown").
type CVEFix struct {
	Name       string `json:"name"`
	FixVersion string `json:"fix_version"`
	FixStatus  string `json:"fix_status"`
	FixOrigin  string `json:"fix_origin"`
}

// CVEPackage is the CVE view of one installed package.
type CVEPackage struct {
	CurrentVersion string   `json:"current_version"`
	CVEs           []CVEFix `json:"cves"`
}

// CVEInfo carries the fields of a CVE's shared metadata that the exporter
// consumes.
type CVEInfo struct {
	Priority string `json:"priority"`
}

// CVEData mirrors data.attributes of u.pro.security.cves.v1: packages maps
// installed package names to their affecting CVEs, and CVEs holds each CVE's
// metadata once.
type CVEData struct {
	Packages map[string]CVEPackage `json:"packages"`
	CVEs     map[string]CVEInfo    `json:"cves"`
}

// Client fetches update status from the Ubuntu Pro client.
type Client interface {
	PackageUpdates(ctx context.Context) (*PackageUpdates, error)
	RebootRequired(ctx context.Context) (*RebootRequired, error)
	InstalledSummary(ctx context.Context) (*InstalledSummary, error)
	PackageManifest(ctx context.Context) ([]InstalledPackage, error)
	CVEs(ctx context.Context) (*CVEData, error)
	IsAttached(ctx context.Context) (bool, error)
	ClientVersion(ctx context.Context) (string, error)
}

// APIError is a failure reported inside a pro api JSON envelope
// (result: "failure").
type APIError struct {
	Code  string
	Title string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("pro api error %s: %s", e.Code, e.Title)
}

// envelope is the outer JSON document every `pro api` call prints.
type envelope struct {
	SchemaVersion string     `json:"_schema_version"`
	Result        string     `json:"result"`
	Errors        []apiError `json:"errors"`
	Data          struct {
		Type       string          `json:"type"`
		Attributes json.RawMessage `json:"attributes"`
	} `json:"data"`
}

type apiError struct {
	Title string `json:"title"`
	Code  string `json:"code"`
}

// ExecClient queries the API by running the pro binary.
//
// Shelling out is the supported integration path: `pro api` is the pro
// client's only stable machine-readable interface (the Python API is
// in-process only, and there is no socket or D-Bus service).
type ExecClient struct {
	// Binary is the pro executable, resolved via $PATH unless it contains
	// a path separator.
	Binary string
	// Timeout bounds a single pro invocation.
	Timeout time.Duration

	// run executes a command and returns its stdout and stderr; it exists so
	// tests can stub process execution.
	run func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

// NewExecClient returns an ExecClient invoking the given pro binary with the
// given per-call timeout.
func NewExecClient(binary string, timeout time.Duration) *ExecClient {
	return &ExecClient{Binary: binary, Timeout: timeout, run: runCmd}
}

func runCmd(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// PackageUpdates returns the pending package updates known to the pro client.
func (c *ExecClient) PackageUpdates(ctx context.Context) (*PackageUpdates, error) {
	attrs, err := c.api(ctx, packageUpdatesEndpoint)
	if err != nil {
		return nil, err
	}
	var pu PackageUpdates
	if err := json.Unmarshal(attrs, &pu); err != nil {
		return nil, fmt.Errorf("parsing %s attributes: %w", packageUpdatesEndpoint, err)
	}
	return &pu, nil
}

// RebootRequired returns the host's reboot-required state.
func (c *ExecClient) RebootRequired(ctx context.Context) (*RebootRequired, error) {
	attrs, err := c.api(ctx, rebootRequiredEndpoint)
	if err != nil {
		return nil, err
	}
	var rr RebootRequired
	if err := json.Unmarshal(attrs, &rr); err != nil {
		return nil, fmt.Errorf("parsing %s attributes: %w", rebootRequiredEndpoint, err)
	}
	return &rr, nil
}

// InstalledSummary returns counts of installed packages by origin.
func (c *ExecClient) InstalledSummary(ctx context.Context) (*InstalledSummary, error) {
	attrs, err := c.api(ctx, packageSummaryEndpoint)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Summary InstalledSummary `json:"summary"`
	}
	if err := json.Unmarshal(attrs, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing %s attributes: %w", packageSummaryEndpoint, err)
	}
	return &wrapper.Summary, nil
}

// PackageManifest returns the installed-package inventory. The manifest_data
// field is a machine-stable tab-separated "package<TAB>version" list, the
// format Ubuntu's CVE scanners consume.
func (c *ExecClient) PackageManifest(ctx context.Context) ([]InstalledPackage, error) {
	attrs, err := c.api(ctx, packageManifestEndpoint)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		ManifestData string `json:"manifest_data"`
	}
	if err := json.Unmarshal(attrs, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing %s attributes: %w", packageManifestEndpoint, err)
	}

	var packages []InstalledPackage
	for _, line := range strings.Split(wrapper.ManifestData, "\n") {
		name, version, found := strings.Cut(strings.TrimSpace(line), "\t")
		if !found || name == "" {
			continue
		}
		packages = append(packages, InstalledPackage{Package: name, Version: version})
	}
	return packages, nil
}

// CVEs returns the CVEs affecting installed packages, evaluated by the pro
// client against Canonical's public vulnerability data. The endpoint exists
// since pro client 35 (check with IsUnsupported) and needs network access to
// refresh its data feed, so a call can take several seconds.
func (c *ExecClient) CVEs(ctx context.Context) (*CVEData, error) {
	attrs, err := c.api(ctx, cvesEndpoint)
	if err != nil {
		return nil, err
	}
	var data CVEData
	if err := json.Unmarshal(attrs, &data); err != nil {
		return nil, fmt.Errorf("parsing %s attributes: %w", cvesEndpoint, err)
	}
	return &data, nil
}

// IsAttached reports whether the host is attached to an Ubuntu Pro
// subscription.
func (c *ExecClient) IsAttached(ctx context.Context) (bool, error) {
	attrs, err := c.api(ctx, isAttachedEndpoint)
	if err != nil {
		return false, err
	}
	var wrapper struct {
		IsAttached bool `json:"is_attached"`
	}
	if err := json.Unmarshal(attrs, &wrapper); err != nil {
		return false, fmt.Errorf("parsing %s attributes: %w", isAttachedEndpoint, err)
	}
	return wrapper.IsAttached, nil
}

// ClientVersion returns the installed pro client version.
func (c *ExecClient) ClientVersion(ctx context.Context) (string, error) {
	attrs, err := c.api(ctx, versionEndpoint)
	if err != nil {
		return "", err
	}
	var wrapper struct {
		InstalledVersion string `json:"installed_version"`
	}
	if err := json.Unmarshal(attrs, &wrapper); err != nil {
		return "", fmt.Errorf("parsing %s attributes: %w", versionEndpoint, err)
	}
	return wrapper.InstalledVersion, nil
}

// IsUnsupported reports whether err means the installed pro client does not
// provide the requested endpoint (an older client), as opposed to the
// endpoint failing.
func IsUnsupported(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == "api-invalid-endpoint"
}

// api invokes `pro api <endpoint>` and returns data.attributes.
//
// pro prints the JSON envelope to stdout even on failure (exit code 1), so
// the envelope's result/errors fields are authoritative. The process error
// and stderr only matter when stdout is not a valid envelope, e.g. the binary
// is missing or the client predates the `pro api` subcommand (27.11).
func (c *ExecClient) api(ctx context.Context, endpoint string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	stdout, stderr, runErr := c.run(ctx, c.Binary, "api", endpoint)

	attrs, parseErr := parseEnvelope(stdout)
	if parseErr != nil {
		// An *APIError means stdout was a well-formed failure envelope; it is
		// authoritative even though pro also exited non-zero. Fall back to the
		// process error only when there was no envelope to speak of.
		var apiErr *APIError
		if runErr != nil && !errors.As(parseErr, &apiErr) {
			return nil, fmt.Errorf("running %s api %s: %w (stderr: %q)", c.Binary, endpoint, runErr, firstLine(stderr))
		}
		return nil, fmt.Errorf("%s api %s: %w", c.Binary, endpoint, parseErr)
	}
	return attrs, nil
}

// parseEnvelope decodes a pro api envelope and returns its data.attributes,
// or the failure it reports.
func parseEnvelope(out []byte) (json.RawMessage, error) {
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("parsing envelope: %w", err)
	}
	if env.Result != "success" {
		if len(env.Errors) > 0 {
			return nil, &APIError{Code: env.Errors[0].Code, Title: env.Errors[0].Title}
		}
		return nil, fmt.Errorf("result %q with no error details", env.Result)
	}
	if len(env.Data.Attributes) == 0 {
		return nil, errors.New("envelope has no data.attributes")
	}
	return env.Data.Attributes, nil
}

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return line
}
