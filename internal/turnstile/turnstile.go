// Package turnstile calls Cloudflare's siteverify. It fails closed: any network, decode or non-success outcome rejects.
package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// ErrFailed is the verdict for a missing, rejected or mismatched token.
var ErrFailed = errors.New("captcha verification failed")

// Verify checks one token. url "" = the real endpoint; the widget's action and hostname must match what the caller expects.
func Verify(ctx context.Context, endpoint, secret, token, ip, action, hostname string) error {
	if token == "" {
		return ErrFailed
	}
	if endpoint == "" {
		endpoint = DefaultURL
	}
	form := url.Values{"secret": {secret}, "response": {token}, "remoteip": {ip}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile siteverify: %w", err)
	}
	defer res.Body.Close()
	var out struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
		Action   string `json:"action"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&out) != nil {
		return fmt.Errorf("turnstile siteverify: status %d", res.StatusCode)
	}
	if !out.Success || out.Action != action || !strings.EqualFold(out.Hostname, hostname) {
		return ErrFailed
	}
	return nil
}
