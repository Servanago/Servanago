package config

import (
	"strings"
	"testing"
)

func TestParseExtraRoutes(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, spec := range []struct{ in, want string }{
			{"/cryptpad_websocket=127.0.0.1:3303", "/cryptpad_websocket=127.0.0.1:3303"},
			{"  /socket=/run/app.sock  \n\n/api=10.0.0.5:9000\n", "/socket=/run/app.sock\n/api=10.0.0.5:9000"},
			{"/trail/=127.0.0.1:1", "/trail=127.0.0.1:1"},
			{"/ws=app_1.local:8080", "/ws=app_1.local:8080"},
		} {
			rs, err := ParseExtraRoutes(spec.in)
			if err != nil {
				t.Errorf("ParseExtraRoutes(%q): %v", spec.in, err)
				continue
			}
			lines := make([]string, len(rs))
			for i, r := range rs {
				lines[i] = r.Text()
			}
			if got := strings.Join(lines, "\n"); got != spec.want {
				t.Errorf("ParseExtraRoutes(%q) = %q, want %q", spec.in, got, spec.want)
			}
		}
	})

	t.Run("rejects", func(t *testing.T) {
		for _, row := range []struct{ in, want string }{
			{"cryptpad=127.0.0.1:3303", "must start with /"},
			{"=127.0.0.1:3303", "must start with /"},
			{"cryptpad_websocket", "path=dial"},
			{"/x=1", "dial"},
			{"/ws=127.0.0.1", "host:port"},
			{"/ws=127.0.0.1:x", "port"},
			{"/ws=127.0.0.1:0", "port"},
			{"/ws=127.0.0.1:65536", "port"},
			{"/ws=127.0.0.1:3303=9", "dial"},
			{"/ws=x y:3303", "dial"},
			{"/foo*=host:3303", "'*'"},
			{"http://x:1=127.0.0.1:2", "must start with /"},
			{"/ws=" + string([]byte{0}) + ":3303", "NUL"},
			{"/" + strings.Repeat("a", 510) + "=h:1", "length"},
		} {
			if _, err := ParseExtraRoutes(row.in); err == nil {
				t.Errorf("ParseExtraRoutes(%q) accepted; want a rejection of %q", row.in, row.want)
			} else if !strings.Contains(err.Error(), row.want) {
				t.Errorf("ParseExtraRoutes(%q) = %q; want it to mention %q", row.in, err.Error(), row.want)
			}
		}
	})
}
