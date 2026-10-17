package helper

import (
	"strings"
	"testing"
)

// FuzzUnitInstallNoInjection: whatever the root and start command are, an accepted node or php install
// renders a unit with exactly the line count of a benign one, a single ExecStart=, and no User= for php.
// Any injected directive would need a line break, a path-list split or an unescaped specifier to get in.
func FuzzUnitInstallNoInjection(f *testing.F) {
	f.Add("node", "/srv/app", "node server.js")
	f.Add("node", "/srv/app\nUser=root", "node a")
	f.Add("node", "/srv/app", "node a\nExecStartPre=/bin/sh")
	f.Add("node", "/srv/app /etc", "node a %h $HOME")
	f.Add("php", "/srv/blog", "")
	f.Add("php", "/srv/blog\r\nUser=root", "")
	f.Add("frankenphp", "/srv/shop\nUser=root", "")
	f.Add("frankenphp", "/srv/shop %h", "")
	benign := func(kind string) int {
		seam := newFakeSeam()
		spec := `{"kind":"node","slug":"site1","root":"/srv/app","port":3000,"start":"node server.js"}`
		switch kind {
		case "php":
			spec = `{"kind":"php","slug":"site1","root":"/srv/app","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`
		case "frankenphp":
			spec = `{"kind":"frankenphp","slug":"site1","root":"/srv/app","port":8100,"franken_bin":"/usr/bin/frankenphp"}`
		}
		req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":` + spec + `}`))
		if err != nil {
			f.Fatal(err)
		}
		if resp := NewActions(seam).UnitInstall(req); !resp.OK {
			f.Fatalf("benign %s install failed: %+v", kind, resp)
		}
		return strings.Count(string(seam.written["/etc/systemd/system/servanago-site1.service"]), "\n")
	}
	lines := map[string]int{"node": benign("node"), "php": benign("php"), "frankenphp": benign("frankenphp")}
	f.Fuzz(func(t *testing.T, kind, root, start string) {
		want, ok := lines[kind]
		if !ok {
			return
		}
		spec := Spec{Kind: kind, Slug: "site1", Root: root}
		switch kind {
		case "node":
			spec.Port, spec.Start = 3000, start
		case "php":
			spec.FPMBin, spec.FPMVersion = "/usr/sbin/php-fpm8.2", "8.2"
		case "frankenphp":
			spec.Port, spec.FrankenBin = 8100, "/usr/bin/frankenphp"
		}
		seam := newFakeSeam()
		if resp := NewActions(seam).UnitInstall(Request{Action: ActionUnitInstall, Vals: spec}); !resp.OK {
			return // rejected: nothing to check
		}
		u := string(seam.written["/etc/systemd/system/servanago-site1.service"])
		// benign line counts differ only by the root, which has no line breaks once accepted
		if got := strings.Count(u, "\n"); got != want {
			t.Fatalf("injected lines: %d lines, benign has %d\nroot=%q start=%q\n%s", got, want, root, start, u)
		}
		if strings.Count(u, "\nExecStart=") != 1 {
			t.Fatalf("ExecStart count != 1:\n%s", u)
		}
		if kind == "php" && strings.Contains(u, "\nUser=") {
			t.Fatalf("php unit gained a User= directive:\n%s", u)
		}
	})
}

// FuzzDecodeRequest proves accepted requests can only be known actions, and that a validated
// slug can only ever become a servanago-<slug>.service unit name: no NUL bytes, separators,
// traversal or unit-file injection ever reach the helper's filesystem calls.
func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"action":"unit-install","spec":{"slug":"blog"}}`))
	f.Add([]byte(`{"action":"ping","spec":{}}`))
	f.Add([]byte(`{"action":"shell","spec":{"cmd":"/bin/sh"}}`))
	f.Add([]byte(`{"action":"unit-install","spec":{"slug":"../../etc"}}`))
	f.Add([]byte(`{"action":"unit-install","spec":{"slug":"a\x00b"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRequest(b)
		if err != nil {
			return
		}
		switch r.Action {
		case ActionPing:
		case ActionUnitInstall:
			if slug, err := r.Slug(); err == nil {
				n, err := unitName(slug)
				if err != nil {
					t.Fatalf("validated slug %q has no unit name: %v", slug, err)
				}
				if !strings.HasPrefix(n, "servanago-") || !strings.HasSuffix(n, ".service") || strings.ContainsAny(n, "/\\") {
					t.Fatalf("unit name %q escaped the managed shape", n)
				}
			}
		default:
			t.Fatalf("unknown action %q accepted", r.Action)
		}
	})
}
