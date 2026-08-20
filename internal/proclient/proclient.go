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
	packageUpdatesEndpoint = "u.pro.packages.updates.v1"
	rebootRequiredEndpoint = "u.pro.security.status.reboot_required.v1"
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

// Client fetches update status from the Ubuntu Pro client.
type Client interface {
	PackageUpdates(ctx context.Context) (*PackageUpdates, error)
	RebootRequired(ctx context.Context) (*RebootRequired, error)
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
