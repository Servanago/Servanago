package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func valid() map[string]string {
	return map[string]string{"CLOUDFLARE_API_TOKEN": strings.Repeat("a", 40), "SERVANAGO_HOST": "servanago.example.com", "ACME_EMAIL": "me@example.com", "SERVANAGO_HOST_IP": "192.168.25.165"}
}

func with(k, v string) map[string]string {
	m := valid()
	m[k] = v
	return m
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want []string // substrings that must appear in the error
	}{
		{"all missing", nil, []string{"SERVANAGO_HOST", "ACME_EMAIL"}},
		{"token without host ip", map[string]string{"CLOUDFLARE_API_TOKEN": strings.Repeat("a", 40), "SERVANAGO_HOST": "h.example.com", "ACME_EMAIL": "me@example.com"}, []string{"SERVANAGO_HOST_IP", "CLOUDFLARE_API_TOKEN"}},
		{"host ip public", with("SERVANAGO_HOST_IP", "203.0.113.10"), []string{"SERVANAGO_HOST_IP", "private"}},
		{"host ip ipv6", with("SERVANAGO_HOST_IP", "fd00::1"), []string{"SERVANAGO_HOST_IP"}},
		{"zone not a suffix of host", with("SERVANAGO_HOST_ZONE", "other.org"), []string{"SERVANAGO_HOST_ZONE"}},
		{"zone is a public suffix-ish single label", with("SERVANAGO_HOST_ZONE", "com"), []string{"SERVANAGO_HOST_ZONE"}},
		{"missing email", map[string]string{"CLOUDFLARE_API_TOKEN": "t", "SERVANAGO_HOST": "h.example.com"}, []string{"ACME_EMAIL"}},
		{"bad email", with("ACME_EMAIL", "not-an-email"), []string{"ACME_EMAIL"}},
		{"display name form", with("ACME_EMAIL", "Name <a@b.co>"), []string{"ACME_EMAIL"}},
		{"bad delay", with("ACME_PROPAGATION_DELAY", "soon"), []string{"ACME_PROPAGATION_DELAY"}},
		{"bad timeout", with("ACME_PROPAGATION_TIMEOUT", "-1m"), []string{"ACME_PROPAGATION_TIMEOUT"}},
		{"bad staging", with("ACME_STAGING", "maybe"), []string{"ACME_STAGING"}},
		{"token too short", with("CLOUDFLARE_API_TOKEN", "tok"), []string{"CLOUDFLARE_API_TOKEN"}},
		{"token quoted", with("CLOUDFLARE_API_TOKEN", `"`+strings.Repeat("a", 40)+`"`), []string{"CLOUDFLARE_API_TOKEN"}},
		{"bad port", with("HTTPS_PORT", "70000"), []string{"HTTPS_PORT"}},
		{"bad host", with("SERVANAGO_HOST", "https://x.example.com"), []string{"SERVANAGO_HOST"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(env(tt.env))
			if err == nil {
				t.Fatal("want error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q missing %q", err, w)
				}
			}
		})
	}
}

func TestNewStyleTokenAccepted(t *testing.T) {
	if _, err := Load(env(with("CLOUDFLARE_API_TOKEN", "cfut_"+strings.Repeat("A", 40)))); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPPort != 80 || c.HTTPSPort != 443 {
		t.Errorf("ports: %d %d", c.HTTPPort, c.HTTPSPort)
	}
	if c.UIListen != "127.0.0.1:8080" || c.DataDir != "/data" || c.Staging || c.AdminPassword != "" {
		t.Errorf("defaults: %+v", c)
	}
	if got := strings.Join(c.Resolvers, ","); got != "1.1.1.1,8.8.8.8" {
		t.Errorf("resolvers %q", got)
	}
	if c.PropagationDelay != 0 || c.PropagationTimeout != 0 {
		t.Errorf("durations should be unset: %+v", c)
	}
}

func TestHostRecordSettings(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil || c.HostIP != "192.168.25.165" || c.HostZone != "" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, z := range []string{"example.com", "servanago.example.com"} { // a zone may be the host itself
		if c, err := Load(env(with("SERVANAGO_HOST_ZONE", z))); err != nil || c.HostZone != z {
			t.Errorf("zone %q: %+v %v", z, c, err)
		}
	}
}

func TestLoadOverrides(t *testing.T) {
	m := valid()
	m["ACME_STAGING"] = "true"
	m["ACME_PROPAGATION_DELAY"] = "2m"
	m["ACME_PROPAGATION_TIMEOUT"] = "10m"
	m["ACME_RESOLVERS"] = " 9.9.9.9 , 1.1.1.1 "
	m["ADMIN_PASSWORD"] = "pw"
	m["UI_LISTEN"] = "0.0.0.0:9000"
	m["DATA_DIR"] = "/tmp/x"
	m["HTTP_PORT"], m["HTTPS_PORT"] = "8000", "8443"
	m["CLOUDFLARE_BASE_URL"] = "http://127.0.0.1:1"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Staging || c.PropagationDelay != 2*time.Minute || c.PropagationTimeout != 10*time.Minute ||
		strings.Join(c.Resolvers, ",") != "9.9.9.9,1.1.1.1" || c.AdminPassword != "pw" ||
		c.UIListen != "0.0.0.0:9000" || c.DataDir != "/tmp/x" || c.HTTPPort != 8000 || c.HTTPSPort != 8443 || c.CFBaseURL != "http://127.0.0.1:1" {
		t.Errorf("%+v", c)
	}
}

func TestAuthHardeningConfig(t *testing.T) {
	key := strings.Repeat("k", 32)
	merge := func(kv ...string) map[string]string {
		m := valid()
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	bad := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"short key", merge("SERVANAGO_SECRET_KEY", "short"), "SERVANAGO_SECRET_KEY"},
		{"require without password", merge("REQUIRE_2FA", "true", "SERVANAGO_SECRET_KEY", key), "ADMIN_PASSWORD"},
		{"require without key", merge("REQUIRE_2FA", "true", "ADMIN_PASSWORD", "pw"), "SERVANAGO_SECRET_KEY"},
		{"require not a bool", merge("REQUIRE_2FA", "yes please"), "REQUIRE_2FA"},
		{"site key alone", merge("TURNSTILE_SITE_KEY", "s"), "TURNSTILE_SECRET"},
		{"secret alone", merge("TURNSTILE_SECRET", "s"), "TURNSTILE_SITE_KEY"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(env(c.env))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error naming %s, got %v", c.want, err)
			}
		})
	}
	c, err := Load(env(merge("REQUIRE_2FA", "true", "ADMIN_PASSWORD", "pw", "SERVANAGO_SECRET_KEY", key,
		"TURNSTILE_SITE_KEY", "site", "TURNSTILE_SECRET", "sec", "TURNSTILE_BASE_URL", "http://x")))
	if err != nil || !c.Require2FA || c.SecretKey != key || c.TurnstileSiteKey != "site" || c.TurnstileSecret != "sec" || c.TurnstileBaseURL != "http://x" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestLoadUsesServanagoEnvNames(t *testing.T) {
	ok := map[string]string{"CLOUDFLARE_API_TOKEN": strings.Repeat("a", 40), "SERVANAGO_HOST": "panel.example.com", "ACME_EMAIL": "me@example.com", "SERVANAGO_HOST_IP": "192.168.25.165"}
	c, err := Load(env(ok))
	if err != nil || c.Host != "panel.example.com" || c.HostIP != "192.168.25.165" {
		t.Fatalf("SERVANAGO_* env not read: %+v, %v", c, err)
	}
	// The old names are not read, and the error names the new variables.
	old := "CARETAK" + "ARR_" // split so a rename sweep does not rewrite the legacy prefix
	_, err = Load(env(map[string]string{"CLOUDFLARE_API_TOKEN": strings.Repeat("a", 40), old + "HOST": "panel.example.com", "ACME_EMAIL": "me@example.com", old + "HOST_IP": "192.168.25.165"}))
	if err == nil || !strings.Contains(err.Error(), "SERVANAGO_HOST") || strings.Contains(err.Error(), old) {
		t.Fatalf("want an error naming SERVANAGO_HOST only, got %v", err)
	}
}

// Cloudflare is optional: without a token ServanaGo serves sites with the default ACME challenges and manages no DNS.
func TestLoadWithoutCloudflare(t *testing.T) {
	c, err := Load(env(map[string]string{"SERVANAGO_HOST": "panel.example.com", "ACME_EMAIL": "me@example.com"}))
	if err != nil {
		t.Fatalf("no token must be valid: %v", err)
	}
	if c.CloudflareToken != "" || c.HostIP != "" {
		t.Errorf("unexpected values: %+v", c)
	}
	if c.DNSEnabled() {
		t.Error("DNS management must be off without a token")
	}
	if _, err := Load(env(map[string]string{"SERVANAGO_HOST": "panel.example.com", "ACME_EMAIL": "me@example.com", "CLOUDFLARE_API_TOKEN": "bad token"})); err == nil {
		t.Error("a malformed token must still be rejected")
	}
	if c, err := Load(env(valid())); err != nil || !c.DNSEnabled() {
		t.Errorf("a valid token turns DNS management on: %v", err)
	}
}

func TestLoadErrorsDoNotAskForCloudflareWhenAbsent(t *testing.T) {
	_, err := Load(env(nil))
	if err == nil || strings.Contains(err.Error(), "CLOUDFLARE_API_TOKEN") || strings.Contains(err.Error(), "SERVANAGO_HOST_IP") {
		t.Fatalf("error must not demand Cloudflare settings: %v", err)
	}
}
