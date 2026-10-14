// Package config parses and validates environment configuration. Secrets live here only.
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	CloudflareToken    string
	Host               string
	ACMEEmail          string
	AdminPassword      string
	Staging            bool
	PropagationDelay   time.Duration // 0 = unset
	PropagationTimeout time.Duration // 0 = unset
	Resolvers          []string
	UIListen           string
	DataDir            string
}

// Load reads configuration through getenv (os.Getenv in production) and reports every problem at once.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	req := func(k string) string {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", k))
		}
		return v
	}
	opt := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	dur := func(k string) time.Duration {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			return 0
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s: %q is not a positive duration", k, v))
			return 0
		}
		return d
	}

	c := Config{
		CloudflareToken:    req("CLOUDFLARE_API_TOKEN"),
		Host:               req("CARETAKARR_HOST"),
		ACMEEmail:          req("ACME_EMAIL"),
		AdminPassword:      getenv("ADMIN_PASSWORD"),
		PropagationDelay:   dur("ACME_PROPAGATION_DELAY"),
		PropagationTimeout: dur("ACME_PROPAGATION_TIMEOUT"),
		UIListen:           opt("UI_LISTEN", "127.0.0.1:8080"),
		DataDir:            opt("DATA_DIR", "/data"),
	}
	for _, r := range strings.Split(opt("ACME_RESOLVERS", "1.1.1.1,8.8.8.8"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			c.Resolvers = append(c.Resolvers, r)
		}
	}
	if v := strings.TrimSpace(getenv("ACME_STAGING")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("ACME_STAGING: %q is not a boolean", v))
		}
		c.Staging = b
	}
	if c.Host != "" {
		if err := ValidateDomain(c.Host); err != nil {
			errs = append(errs, fmt.Errorf("CARETAKARR_HOST: %w", err))
		}
	}
	if c.ACMEEmail != "" {
		// Bare address only: ParseAddress also accepts "Name <a@b>", which Caddy would pass through verbatim.
		if a, err := mail.ParseAddress(c.ACMEEmail); err != nil || a.Address != c.ACMEEmail {
			errs = append(errs, fmt.Errorf("ACME_EMAIL: %q is not a bare email address", c.ACMEEmail))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, fmt.Errorf("invalid configuration: %w", err)
	}
	return c, nil
}
