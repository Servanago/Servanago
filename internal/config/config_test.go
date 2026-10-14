package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func valid() map[string]string {
	return map[string]string{"CLOUDFLARE_API_TOKEN": strings.Repeat("a", 40), "CARETAKARR_HOST": "caretakarr.example.com", "ACME_EMAIL": "me@example.com", "CARETAKARR_HOST_IP": "192.168.25.165"}
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
		{"all missing", nil, []string{"CLOUDFLARE_API_TOKEN", "CARETAKARR_HOST", "ACME_EMAIL", "CARETAKARR_HOST_IP"}},
		{"host ip public", with("CARETAKARR_HOST_IP", "203.0.113.10"), []string{"CARETAKARR_HOST_IP", "private"}},
		{"host ip ipv6", with("CARETAKARR_HOST_IP", "fd00::1"), []string{"CARETAKARR_HOST_IP"}},
		{"zone not a suffix of host", with("CARETAKARR_HOST_ZONE", "other.org"), []string{"CARETAKARR_HOST_ZONE"}},
		{"zone is a public suffix-ish single label", with("CARETAKARR_HOST_ZONE", "com"), []string{"CARETAKARR_HOST_ZONE"}},
		{"missing email", map[string]string{"CLOUDFLARE_API_TOKEN": "t", "CARETAKARR_HOST": "h.example.com"}, []string{"ACME_EMAIL"}},
		{"bad email", with("ACME_EMAIL", "not-an-email"), []string{"ACME_EMAIL"}},
		{"display name form", with("ACME_EMAIL", "Name <a@b.co>"), []string{"ACME_EMAIL"}},
		{"bad delay", with("ACME_PROPAGATION_DELAY", "soon"), []string{"ACME_PROPAGATION_DELAY"}},
		{"bad timeout", with("ACME_PROPAGATION_TIMEOUT", "-1m"), []string{"ACME_PROPAGATION_TIMEOUT"}},
		{"bad staging", with("ACME_STAGING", "maybe"), []string{"ACME_STAGING"}},
		{"token too short", with("CLOUDFLARE_API_TOKEN", "tok"), []string{"CLOUDFLARE_API_TOKEN"}},
		{"token quoted", with("CLOUDFLARE_API_TOKEN", `"`+strings.Repeat("a", 40)+`"`), []string{"CLOUDFLARE_API_TOKEN"}},
		{"bad port", with("HTTPS_PORT", "70000"), []string{"HTTPS_PORT"}},
		{"bad host", with("CARETAKARR_HOST", "https://x.example.com"), []string{"CARETAKARR_HOST"}},
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
	if c.DockerSocket != "/var/run/docker.sock" {
		t.Errorf("docker socket default: %q", c.DockerSocket)
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
	for _, z := range []string{"example.com", "caretakarr.example.com"} { // a zone may be the host itself
		if c, err := Load(env(with("CARETAKARR_HOST_ZONE", z))); err != nil || c.HostZone != z {
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
