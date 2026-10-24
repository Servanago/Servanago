// Package helper is the privileged helper: a small root daemon the control plane asks to do
// typed host work over a Unix socket (see `servanago helper`). The peer must be root or the
// servanago user; every action field is validated here, and unit files are written only from
// the helper's own template as `servanago-<slug>.service` — never from caller-supplied content.
package helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/servanago/servanago/internal/phpbuild"
)

const (
	ActionPing        = "ping"
	ActionUnitInstall = "unit-install"
	ActionUnitStatus  = "unit-status"
	ActionUnitLogs    = "unit-logs"
	ActionUserAdd     = "user-add"
	ActionUserCheck   = "user-check"
	ActionUserRemove  = "user-remove"
	ActionUnitRemove  = "unit-remove"
	ActionUnitStart   = "unit-start"
	ActionUnitStop    = "unit-stop"
	ActionDockerList  = "docker-list"

	ActionPHPBuild       = "php-build"
	ActionPHPStatus      = "php-status"
	ActionPHPInstall     = "php-install"
	ActionPHPPrune       = "php-prune"
	ActionPHPUserDefault = "php-user-default"
	ActionComposer       = "composer-install"

	ActionBackupEnable  = "backup-enable"
	ActionBackupStart   = "backup-start"
	ActionBackupRestore = "backup-restore"
	ActionBackupStatus  = "backup-status"
)

// MaxRequestSize bounds one request; larger input is refused before parsing.
const MaxRequestSize = 64 << 10

var slugRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// ValidateSlug checks a site slug: 2-32 characters of a-z, 0-9 and '-', starting with a letter.
// Unit names and managed paths are derived from validated slugs only, so this is the trust boundary.
func ValidateSlug(s string) error {
	if !slugRE.MatchString(s) {
		return fmt.Errorf("slug %q must be 2-32 characters of a-z, 0-9 and '-', starting with a letter", s)
	}
	return nil
}

// unitName builds the host unit name inside the helper only: callers never supply it.
func unitName(slug string) (string, error) {
	if err := ValidateSlug(slug); err != nil {
		return "", err
	}
	return "servanago-" + slug + ".service", nil
}

// Spec carries the validated fields of one action; unknown fields are refused at decode.
// Lines is the unit-logs tail size (0 = default); the unit-install fields are kind-specific
// and validated per kind in the helper.
type Spec struct {
	Slug       string `json:"slug,omitempty"`
	Lines      int    `json:"lines,omitempty"`
	Kind       string `json:"kind,omitempty"`        // unit-install: node | php | frankenphp | cgi
	Root       string `json:"root,omitempty"`        // node | php | frankenphp | user-add: site directory
	Port       int    `json:"port,omitempty"`        // node | frankenphp: the app's port
	Start      string `json:"start,omitempty"`       // node: the start command (runs as the site user)
	FPMBin     string `json:"fpm_bin,omitempty"`     // php: detected binary
	FPMVersion string `json:"fpm_version,omitempty"` // php: label matching FPMBin's suffix
	FrankenBin string `json:"franken_bin,omitempty"` // frankenphp: detected binary (one of a fixed set)
	FCGIBin    string `json:"fcgi_bin,omitempty"`    // cgi: detected fcgiwrap (one of a fixed set)

	Extensions []string `json:"extensions,omitempty"`  // php (source build): shared extensions from the allowlist; none = the core set
	PHPVersion string   `json:"php_version,omitempty"` // php-build/php-install: 8.4.27; php-user-default: a label (8.4 or 8.4.27-1), "" clears
	User       string   `json:"user,omitempty"`        // php-user-default: an existing login user; unit-install and user-add: the site's named user ("" = generated sg-<slug>)
	Build      string   `json:"build,omitempty"`       // php-prune: a build directory name such as 8.4.27-1
	Home       string   `json:"home,omitempty"`        // user-add: home of a user to create (under /home or /srv)
	Shell      bool     `json:"shell,omitempty"`       // user-add: the created user gets a login shell (else nologin)
	Public     string   `json:"public,omitempty"`      // unit-install, user-add: the served folder inside Root (php, frankenphp, static); "" = Root

	Enabled      bool   `json:"enabled,omitempty"`       // backup-enable: install the timer (false removes it)
	Scope        string `json:"scope,omitempty"`         // backup-start: all | panel | site (site takes Slug)
	Archive      string `json:"archive,omitempty"`       // backup-restore: an archive file name of the site
	RestoreFiles bool   `json:"restore_files,omitempty"` // backup-restore
	RestoreDumps bool   `json:"restore_dumps,omitempty"` // backup-restore
	Actor        string `json:"actor,omitempty"`         // backup-start|restore: the signed-in user, for the audit row

	RestoreVolumes []string `json:"restore_volumes,omitempty"` // backup-restore: docker volume names (at most 20); the job stops their containers
}

// UserData is what user-check and user-add report about a named site user.
type UserData struct {
	Exists bool   `json:"exists"`
	Home   string `json:"home,omitempty"`
	Group  string `json:"group,omitempty"` // the user's primary group
	Login  bool   `json:"login,omitempty"` // has a login shell
}

// Request is one newline-delimited action from the control plane. Spec is mandatory, even
// for ping, so every request parses through the same strict decoder; Vals is the decoded Spec.
type Request struct {
	Action string          `json:"action"`
	Spec   json.RawMessage `json:"spec"`
	Vals   Spec            `json:"-"`
}

// DecodeRequest parses exactly one request: size-bounded, strict on unknown fields, action
// in the closed set, spec shape checked. Field values (the slug) are validated by the caller
// of the action, never trusted here.
func DecodeRequest(b []byte) (Request, error) {
	if len(b) > MaxRequestSize {
		return Request{}, fmt.Errorf("request of %d bytes exceeds the %d byte limit", len(b), MaxRequestSize)
	}
	var r Request
	if err := strict(bytes.NewReader(b)).Decode(&r); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	switch r.Action {
	case ActionPing, ActionUnitInstall, ActionUnitStatus, ActionUnitLogs,
		ActionUserAdd, ActionUserCheck, ActionUserRemove, ActionUnitRemove, ActionUnitStart, ActionUnitStop, ActionDockerList,
		ActionPHPBuild, ActionPHPStatus, ActionPHPInstall, ActionPHPPrune, ActionPHPUserDefault, ActionComposer,
		ActionBackupEnable, ActionBackupStart, ActionBackupRestore, ActionBackupStatus:
	default:
		return Request{}, fmt.Errorf("unknown action %q", r.Action)
	}
	var s Spec
	if err := strict(bytes.NewReader(r.Spec)).Decode(&s); err != nil {
		return Request{}, fmt.Errorf("decode spec for %s: %w", r.Action, err)
	}
	r.Vals = s
	return r, nil
}

// Slug returns the spec's slug for actions that carry one; SlugErr reports why it is invalid.
func (r Request) Slug() (string, error) {
	if err := ValidateSlug(r.Vals.Slug); err != nil {
		return "", err
	}
	return r.Vals.Slug, nil
}

// SpecLines returns the log tail size the spec asks for; 0 means the action default.
func (r Request) SpecLines() int {
	return r.Vals.Lines
}

func strict(r *bytes.Reader) *json.Decoder {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	return d
}

// Response answers one request. Only the fields the action produces are set.
type Response struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Status *StatusData     `json:"status,omitempty"`
	Logs   []string        `json:"logs,omitempty"`
	Build  *phpbuild.State `json:"build,omitempty"`  // php-status
	User   *UserData       `json:"user,omitempty"`   // user-check, user-add with a named user
	Docker *DockerData     `json:"docker,omitempty"` // docker-list
}

// StatusData is one unit's systemd state.
type StatusData struct {
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	PID         string `json:"pid,omitempty"`
}
