package helper

import (
	"strings"
	"testing"
)

// TestRuntimeUnitInstall covers node and php unit installs; the placeholder template is gone.
func TestRuntimeUnitInstall(t *testing.T) {
	tests := []struct {
		name, slug, spec string
	}{
		{"node", "app11", `{"kind":"node","slug":"app11","root":"/home/brian/app11","port":3000,"start":"node server.js"}`},
		{"php", "blog", `{"kind":"php","slug":"blog","root":"/home/brian/blog","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newFakeSeam()
			req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":` + tt.spec + `}`))
			if err != nil {
				t.Fatal(err)
			}
			resp := NewActions(seam).UnitInstall(req)
			if !resp.OK {
				t.Fatalf("%s install failed: %+v", tt.name, resp)
			}
			unitPath := "/etc/systemd/system/servanago-" + tt.slug + ".service"
			unit, ok := seam.written[unitPath]
			if !ok {
				t.Fatalf("no unit written: path=%q written=%v", unitPath, seam.written)
			}
			u := string(unit)
			if !strings.Contains(u, "User=sg-"+tt.slug) {
				t.Errorf("unit not run as site user:\n%s", u)
			}
			if !strings.Contains(u, "ProtectSystem=strict") || strings.Contains(u, "ProtectHome=yes") {
				t.Errorf("unit sandbox wrong:\n%s", u)
			}
			switch tt.name {
			case "node":
				if !strings.Contains(u, `ExecStart=/bin/sh -c 'node server.js'`) {
					t.Errorf("node start missing:\n%s", u)
				}
				if !strings.Contains(u, "ReadWritePaths=/home/brian/app11") || !strings.Contains(u, "WorkingDirectory=/home/brian/app11") {
					t.Errorf("node paths wrong:\n%s", u)
				}
				if len(seam.written) != 1 {
					t.Errorf("node wrote extra files: %v", keys(seam.written))
				}
			case "php":
				pool, ok := seam.written["/etc/servanago/fpm/blog.conf"]
				if !ok {
					t.Fatalf("no pool written: %v", keys(seam.written))
				}
				p := string(pool)
				for _, want := range []string{"listen=/run/servanago/blog.sock", "user=sg-blog", "listen.owner=servanago", "[servanago-blog]", "pm=dynamic"} {
					if !strings.Contains(p, want) {
						t.Errorf("pool missing %q:\n%s", want, p)
					}
				}
				if seam.fpmTested != "/etc/servanago/fpm/blog.conf" || seam.fpmTestBin != "/usr/sbin/php-fpm8.2" {
					t.Errorf("pool not tested: bin=%q conf=%q", seam.fpmTestBin, seam.fpmTested)
				}
			}
			if seam.reloadCalls != 1 || seam.enabled != "servanago-"+tt.slug+".service" {
				t.Errorf("reload=%d enable=%q", seam.reloadCalls, seam.enabled)
			}
		})
	}
}

func TestRuntimeUnitInstallRejections(t *testing.T) {
	tests := []struct {
		name, spec string
	}{
		{"unknown kind", `{"kind":"cgi","slug":"x"}`},
		{"node no start", `{"kind":"node","slug":"x","root":"/srv/x","port":3000,"start":""}`},
		{"node NUL start", `{"kind":"node","slug":"x","root":"/srv/x","port":3000,"start":"a` + `\u0000b"` + `}`},
		{"node overlong start", `{"kind":"node","slug":"x","root":"/srv/x","port":3000,"start":"` + strings.Repeat("a", 3000) + `"}`},
		{"node relative root", `{"kind":"node","slug":"x","root":"srv/x","port":3000,"start":"node a"}`},
		{"node bad port", `{"kind":"node","slug":"x","root":"/srv/x","port":80,"start":"node a"}`},
		{"php bad binary name", `{"kind":"php","slug":"x","root":"/srv/x","fpm_bin":"/bin/sh","fpm_version":"8.2"}`},
		{"php mismatched version", `{"kind":"php","slug":"x","root":"/srv/x","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.1"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newFakeSeam()
			req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":` + tt.spec + `}`))
			if err != nil {
				t.Fatal(err)
			}
			if resp := NewActions(seam).UnitInstall(req); resp.OK {
				t.Fatalf("accepted: %+v", resp)
			}
			if len(seam.written) != 0 {
				t.Errorf("host was written: %v", keys(seam.written))
			}
		})
	}
}

func TestUserAndUnitLifecycle(t *testing.T) {
	seam := newFakeSeam()
	acts := NewActions(seam)
	// user-add: creates sg-<slug> and hands the root to it.
	req, err := DecodeRequest([]byte(`{"action":"user-add","spec":{"slug":"app11","root":"/srv/app11"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp := acts.UserAdd(req); !resp.OK {
		t.Fatalf("user-add: %+v", resp)
	}
	if seam.userAdded != "sg-app11" || len(seam.chowned) != 1 || seam.chowned[0].user != "sg-app11" {
		t.Fatalf("user-add seam: %+v %+v", seam.userAdded, seam.chowned)
	}
	// unit-start / unit-stop / unit-remove
	start, _ := DecodeRequest([]byte(`{"action":"unit-start","spec":{"slug":"app11"}}`))
	if resp := acts.UnitStart(start); !resp.OK || seam.started != "servanago-app11.service" {
		t.Fatalf("unit-start: %+v %q", resp, seam.started)
	}
	stop, _ := DecodeRequest([]byte(`{"action":"unit-stop","spec":{"slug":"app11"}}`))
	_ = acts.UnitStop(stop)
	if seam.stopped != "servanago-app11.service" {
		t.Fatalf("unit-stop: %q", seam.stopped)
	}
	rm, _ := DecodeRequest([]byte(`{"action":"unit-remove","spec":{"slug":"app11"}}`))
	if resp := acts.UnitRemove(rm); !resp.OK {
		t.Fatalf("unit-remove: %+v", resp)
	}
	if seam.disabled != "servanago-app11.service" || seam.removed == "" {
		t.Fatalf("unit-remove left state: disabled=%q removed=%q", seam.disabled, seam.removed)
	}
	// user-remove
	usr, _ := DecodeRequest([]byte(`{"action":"user-remove","spec":{"slug":"app11"}}`))
	if resp := acts.UserRemove(usr); !resp.OK || seam.userRemoved != "sg-app11" {
		t.Fatalf("user-remove: %+v %q", resp, seam.userRemoved)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
