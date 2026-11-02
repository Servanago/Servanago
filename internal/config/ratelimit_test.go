package config

import "testing"

func TestRLWindow(t *testing.T) {
	rows := []struct {
		in      string
		secs    int
		canon   string
		wantErr bool
	}{
		{"1m", 60, "1m", false},
		{"5m", 300, "5m", false},
		{"1h", 3600, "1h", false},
		{"", 0, "", false},
		{" 5m ", 300, "5m", false},
		{"1d", 0, "", true},
		{"60", 0, "", true},
	}
	for _, row := range rows {
		secs, canon, err := RLWindow(row.in)
		if err != nil != row.wantErr {
			t.Errorf("RLWindow(%q) err = %v", row.in, err)
		}
		if err == nil && (secs != row.secs || canon != row.canon) {
			t.Errorf("RLWindow(%q) = %d %q, want %d %q", row.in, secs, canon, row.secs, row.canon)
		}
	}
}

func TestParseRLPaths(t *testing.T) {
	rows := []struct {
		name   string
		in     string
		want   string
		errSub string
	}{
		{"blank", "", "", ""},
		{"one", "/login", "/login", ""},
		{"trailing slash drops", "/cart/checkout/", "/cart/checkout", ""},
		{"cr-lf", "/login\r\n/cart", "/login\n/cart", ""},
		{"relative path", "login", "", "must start with /"},
		{"wildcards", "/a*", "", "'*'"},
		{"traversal", "/a/../b", "", "'..'"},
	}
	for _, row := range rows {
		_, err := ParseRLPaths(row.in)
		switch {
		case row.errSub != "":
			if err == nil || !containsString(err.Error(), row.errSub) {
				t.Errorf("%s: ParseRLPaths(%q) = %v, want error naming %q", row.name, row.in, err, row.errSub)
			}
		default:
			if err != nil {
				t.Errorf("%s: ParseRLPaths(%q) errored: %v", row.name, row.in, err)
			}
		}
	}
	canonical, err := ParseRLPaths(" /login \r\n/cart/checkout/ \n\n")
	if err != nil || joinLines(canonical) != "/login\n/cart/checkout" {
		t.Errorf("canonical form: %q (%v)", canonical, err)
	}
}

func containsString(s, want string) bool {
	for i := 0; i+len(want) <= len(s); i++ {
		if s[i:i+len(want)] == want {
			return true
		}
	}
	return false
}

func joinLines(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += "\n"
		}
		out += x
	}
	return out
}
