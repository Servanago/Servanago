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
)

const (
	ActionPing        = "ping"
	ActionUnitInstall = "unit-install"
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
type Spec struct {
	Slug string `json:"slug,omitempty"`
}

// Request is one newline-delimited action from the control plane. Spec is mandatory, even
// for ping, so every request parses through the same strict decoder.
type Request struct {
	Action string          `json:"action"`
	Spec   json.RawMessage `json:"spec"`
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
	case ActionPing, ActionUnitInstall:
	default:
		return Request{}, fmt.Errorf("unknown action %q", r.Action)
	}
	var s Spec
	if err := strict(bytes.NewReader(r.Spec)).Decode(&s); err != nil {
		return Request{}, fmt.Errorf("decode spec for %s: %w", r.Action, err)
	}
	return r, nil
}

// Slug returns the spec's slug for actions that carry one; SlugErr reports why it is invalid.
func (r Request) Slug() (string, error) {
	var s Spec
	if err := json.Unmarshal(r.Spec, &s); err != nil {
		return "", err
	}
	if err := ValidateSlug(s.Slug); err != nil {
		return "", err
	}
	return s.Slug, nil
}

func strict(r *bytes.Reader) *json.Decoder {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	return d
}

// Response answers one request. Data fields arrive with the actions that need them (M5+).
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}