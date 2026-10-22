package helper

import (
	"errors"
	"fmt"
	"path/filepath"
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
		{"frankenphp", "shop", `{"kind":"frankenphp","slug":"shop","root":"/home/brian/shop","port":8100,"franken_bin":"/usr/local/bin/frankenphp"}`},
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
			if !strings.Contains(u, "ProtectSystem=strict") || strings.Contains(u, "ProtectHome=yes") {
				t.Errorf("unit sandbox wrong:\n%s", u)
			}
			// The site's folder is writable by the unit: apps write uploads, caches and sessions there.
			if !strings.Contains(u, "ReadWritePaths=") || !strings.Contains(u, "/home/brian/"+tt.slug) {
				t.Errorf("unit cannot write the site folder:\n%s", u)
			}
			switch tt.name {
			case "node":
				// The app itself runs as the unprivileged site user, never root.
				if !strings.Contains(u, "User=sg-"+tt.slug) {
					t.Errorf("node unit not run as site user:\n%s", u)
				}
				if !strings.Contains(u, `ExecStart=/bin/sh -c 'node server.js'`) {
					t.Errorf("node start missing:\n%s", u)
				}
				if !strings.Contains(u, "ReadWritePaths=/home/brian/app11") || !strings.Contains(u, "WorkingDirectory=/home/brian/app11") {
					t.Errorf("node paths wrong:\n%s", u)
				}
				if len(seam.written) != 1 {
					t.Errorf("node wrote extra files: %v", keys(seam.written))
				}
			case "frankenphp":
				for _, want := range []string{"User=sg-shop", "ExecStart=/usr/local/bin/frankenphp php-server --root /home/brian/shop --listen 127.0.0.1:8100",
					"XDG_DATA_HOME=/tmp/xdg-data", "ReadWritePaths=/home/brian/shop", "WorkingDirectory=/home/brian/shop"} {
					if !strings.Contains(u, want) {
						t.Errorf("frankenphp unit missing %q:\n%s", want, u)
					}
				}
				if seam.binChecked != "/usr/local/bin/frankenphp" || len(seam.written) != 1 {
					t.Errorf("binary check %q, files %v", seam.binChecked, keys(seam.written))
				}
			case "php":
				// php-fpm's own model: the master (root) creates the socket in the root-owned /run/servanago
				// and its workers drop to the site user through the pool's user=. A master started as the site
				// user could not create the socket at all.
				if strings.Contains(u, "\nUser=") {
					t.Errorf("php master must start as root and drop privileges in the pool:\n%s", u)
				}
				// The socket directory outlives the helper unit: systemd would otherwise delete every site socket
				// when the helper restarts.
				for _, want := range []string{"RuntimeDirectory=servanago", "RuntimeDirectoryPreserve=yes", "ReadWritePaths=/run/servanago"} {
					if !strings.Contains(u, want) {
						t.Errorf("php unit missing %q:\n%s", want, u)
					}
				}
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
				// Logs go to the journal: the site user cannot write /var/log/servanago. With no error_log a foreground
				// php-fpm writes to its stderr; /proc/self/fd/2 fails with ENXIO when stderr is the journald socket.
				if strings.Contains(p, "/var/log/") || strings.Contains(p, "error_log") {
					t.Errorf("pool must leave error_log unset (stderr, journald):\n%s", p)
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
	// Every row uses a valid slug, so a row can only pass by being rejected for the reason named in want.
	// (An earlier version used a one-letter slug, which ValidateSlug rejects: the whole table passed vacuously.)
	const nodeHead = `{"kind":"node","slug":"site1","port":3000,`
	const phpHead = `{"kind":"php","slug":"site1","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2",`
	const frankenBin = "/usr/bin/frankenphp"
	const frankenHead = `{"kind":"frankenphp","slug":"site1","port":8100,`
	tests := []struct{ name, spec, want string }{
		{"unknown kind", `{"kind":"ruby","slug":"site1"}`, "kind"},
		{"bad slug", `{"kind":"node","slug":"../x","root":"/srv/x","port":3000,"start":"node a"}`, "slug"},
		{"node no start", nodeHead + `"root":"/srv/x","start":""}`, "start"},
		{"node NUL start", nodeHead + `"root":"/srv/x","start":"a\u0000b"}`, "start"},
		{"node overlong start", nodeHead + `"root":"/srv/x","start":"` + strings.Repeat("a", 3000) + `"}`, "start"},
		{"node relative root", nodeHead + `"root":"srv/x","start":"node a"}`, "root"},
		{"node bad port", `{"kind":"node","slug":"site1","port":80,"root":"/srv/x","start":"node a"}`, "port"},
		// Unit-file injection: a line break would add directives such as User=root or ExecStartPre=.
		{"node newline start", nodeHead + `"root":"/srv/x","start":"node a\nUser=root"}`, "start"},
		{"node CR start", nodeHead + `"root":"/srv/x","start":"node a\rUser=root"}`, "start"},
		{"node newline root", nodeHead + `"root":"/srv/x\nUser=root","start":"node a"}`, "root"},
		{"node space root", nodeHead + `"root":"/srv/x /etc","start":"node a"}`, "root"},
		{"node traversal root", nodeHead + `"root":"/srv/../etc","start":"node a"}`, "root"},
		{"php newline root", phpHead + `"root":"/srv/x\nUser=root"}`, "root"},
		{"php space root", phpHead + `"root":"/srv/x /etc"}`, "root"},
		{"php traversal root", phpHead + `"root":"/srv/../etc"}`, "root"},
		{"php bad binary name", `{"kind":"php","slug":"site1","root":"/srv/x","fpm_bin":"/bin/sh","fpm_version":"8.2"}`, "php-fpm binary"},
		{"php mismatched version", `{"kind":"php","slug":"site1","root":"/srv/x","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.1"}`, "version"},
		{"franken unknown binary", frankenHead + `"root":"/srv/x","franken_bin":"/bin/sh"}`, "frankenphp binary"},
		{"franken traversal binary", frankenHead + `"root":"/srv/x","franken_bin":"/usr/bin/../../tmp/frankenphp"}`, "frankenphp binary"},
		{"franken no binary", frankenHead + `"root":"/srv/x"}`, "frankenphp binary"},
		{"franken bad port", `{"kind":"frankenphp","slug":"site1","port":80,"root":"/srv/x","franken_bin":"` + frankenBin + `"}`, "port"},
		{"cgi unknown binary", `{"kind":"cgi","slug":"site1","root":"/srv/x","fcgi_bin":"/bin/sh"}`, "fcgiwrap binary"},
		{"cgi no binary", `{"kind":"cgi","slug":"site1","root":"/srv/x"}`, "fcgiwrap binary"},
		{"cgi newline root", `{"kind":"cgi","slug":"site1","root":"/srv/x\nUser=root","fcgi_bin":"/usr/sbin/fcgiwrap"}`, "root"},
		{"cgi space root", `{"kind":"cgi","slug":"site1","root":"/srv/x /etc","fcgi_bin":"/usr/sbin/fcgiwrap"}`, "root"},
		{"franken newline root", frankenHead + `"root":"/srv/x\nUser=root","franken_bin":"` + frankenBin + `"}`, "root"},
		{"franken space root", frankenHead + `"root":"/srv/x /etc","franken_bin":"` + frankenBin + `"}`, "root"},
		{"franken relative root", frankenHead + `"root":"srv/x","franken_bin":"` + frankenBin + `"}`, "root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newFakeSeam()
			req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":` + tt.spec + `}`))
			if err != nil {
				t.Fatal(err)
			}
			resp := NewActions(seam).UnitInstall(req)
			if resp.OK {
				t.Fatalf("accepted: %+v", resp)
			}
			if !strings.Contains(resp.Error, tt.want) {
				t.Errorf("rejected for the wrong reason: %q does not mention %q", resp.Error, tt.want)
			}
			if len(seam.written) != 0 {
				t.Errorf("host was written: %v", keys(seam.written))
			}
		})
	}
}

// A binary the site user could have replaced is refused before anything is written.
func TestFrankenBinaryMustBeTrusted(t *testing.T) {
	seam := newFakeSeam()
	seam.binErr = errors.New("must be owned by root")
	req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":{"kind":"frankenphp","slug":"site1","root":"/srv/x","port":8100,"franken_bin":"/usr/bin/frankenphp"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := NewActions(seam).UnitInstall(req)
	if resp.OK || !strings.Contains(resp.Error, "owned by root") || len(seam.written) != 0 {
		t.Fatalf("untrusted binary accepted: %+v written=%v", resp, keys(seam.written))
	}
}

// A failed verify rolls the new unit back; if the rollback itself fails the caller must be told, because
// a bad unit file is then still on disk.
func TestVerifyFailureRollbackIsReported(t *testing.T) {
	seam := newFakeSeam()
	seam.verify = errors.New("bad unit")
	seam.removeErr = errors.New("read-only filesystem")
	req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":{"kind":"node","slug":"site1","root":"/srv/x","port":3000,"start":"node a"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := NewActions(seam).UnitInstall(req)
	if resp.OK || !strings.Contains(resp.Error, "bad unit") || !strings.Contains(resp.Error, "read-only filesystem") {
		t.Fatalf("response must report both the verify failure and the failed rollback: %+v", resp)
	}
}

// systemd expands % specifiers and $VAR in ExecStart even inside a shell -c string. The admin's start
// command is data for sh, not for systemd, so both must reach the shell untouched.
func TestNodeStartCommandIsEscapedForSystemd(t *testing.T) {
	seam := newFakeSeam()
	req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":{"kind":"node","slug":"app11","root":"/srv/app11","port":3000,` +
		`"start":"node server.js --name %h --home $HOME --it's ${PORT}"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp := NewActions(seam).UnitInstall(req); !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
	u := string(seam.written["/etc/systemd/system/servanago-app11.service"])
	want := `ExecStart=/bin/sh -c 'node server.js --name %%h --home $$HOME --it'\''s $${PORT}'`
	if !strings.Contains(u, want) {
		t.Errorf("start command not escaped\nwant line %s\ngot:\n%s", want, u)
	}
	if strings.Count(u, "\nExecStart=") != 1 {
		t.Errorf("exactly one ExecStart expected:\n%s", u)
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
	// The user's home is the site folder, but ServanaGo never changes ownership or permissions of the
	// admin's files: the seam gets no chown, only the home directory to record.
	if seam.userAdded != "sg-app11" || seam.userHome != "/srv/app11" {
		t.Fatalf("user-add seam: user %q home %q", seam.userAdded, seam.userHome)
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

func TestCGIUnitInstall(t *testing.T) {
	seam := newFakeSeam()
	req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":{"kind":"cgi","slug":"legacy","root":"/home/brian/legacy","fcgi_bin":"/usr/sbin/fcgiwrap"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp := NewActions(seam).UnitInstall(req); !resp.OK {
		t.Fatalf("install: %+v", resp)
	}
	svc := string(seam.written["/etc/systemd/system/servanago-legacy.service"])
	sock := string(seam.written["/etc/systemd/system/servanago-legacy.socket"])
	for _, want := range []string{"User=sg-legacy", "ExecStart=/usr/sbin/fcgiwrap\n", "ReadWritePaths=/home/brian/legacy", "Requires=servanago-legacy.socket"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %q:\n%s", want, svc)
		}
	}
	if strings.Contains(svc, "[Install]") {
		t.Errorf("the service is socket-activated, not enabled:\n%s", svc)
	}
	for _, want := range []string{"ListenStream=/run/servanago/legacy.sock", "SocketUser=servanago", "SocketMode=0660"} {
		if !strings.Contains(sock, want) {
			t.Errorf("socket missing %q:\n%s", want, sock)
		}
	}
	// The socket is what gets enabled; the binary is checked first.
	if seam.enabled != "servanago-legacy.socket" || seam.binChecked != "/usr/sbin/fcgiwrap" || len(seam.written) != 2 {
		t.Errorf("enabled=%q binChecked=%q files=%v", seam.enabled, seam.binChecked, keys(seam.written))
	}
}

// For a cgi site start, stop, status and remove act on the socket unit as well as the service.
func TestCGILifecycleUsesSocket(t *testing.T) {
	seam := newFakeSeam()
	seam.atUnit = "/etc/systemd/system/servanago-legacy.socket"
	acts := NewActions(seam)
	start, _ := DecodeRequest([]byte(`{"action":"unit-start","spec":{"slug":"legacy"}}`))
	if resp := acts.UnitStart(start); !resp.OK || seam.started != "servanago-legacy.socket" {
		t.Fatalf("start: %+v %q", resp, seam.started)
	}
	stat, _ := DecodeRequest([]byte(`{"action":"unit-status","spec":{"slug":"legacy"}}`))
	if resp := acts.UnitStatus(stat); !resp.OK || seam.statusName != "servanago-legacy.socket" {
		t.Fatalf("status: %+v %q", resp, seam.statusName)
	}
	rm, _ := DecodeRequest([]byte(`{"action":"unit-remove","spec":{"slug":"legacy"}}`))
	if resp := acts.UnitRemove(rm); !resp.OK || seam.disabled != "servanago-legacy.service" || seam.stopped != "servanago-legacy.service" {
		t.Fatalf("remove: %+v disabled=%q stopped=%q", resp, seam.disabled, seam.stopped)
	}
	// A site without a socket keeps acting on the service.
	plain := newFakeSeam()
	start2, _ := DecodeRequest([]byte(`{"action":"unit-start","spec":{"slug":"app11"}}`))
	if resp := NewActions(plain).UnitStart(start2); !resp.OK || plain.started != "servanago-app11.service" {
		t.Fatalf("plain start: %+v %q", resp, plain.started)
	}
}

// loadSeam verifies like systemd-analyze: a .service that Requires= a socket (and the socket's service) must already be on disk.
type loadSeam struct{ *fakeSeam }

func (s loadSeam) VerifyUnit(path string) error {
	sibling := map[string]string{".service": ".socket", ".socket": ".service"}[filepath.Ext(path)]
	if _, ok := s.written[strings.TrimSuffix(path, filepath.Ext(path))+sibling]; !ok {
		return fmt.Errorf("%s: unit %s not found", filepath.Base(path), sibling)
	}
	return nil
}

func TestSocketSiteVerifiesWithItsSocketOnDisk(t *testing.T) {
	for _, tt := range []struct {
		seam *fakeSeam
		spec string
	}{
		{newFakeSeam(), `{"kind":"cgi","slug":"legacy","root":"/home/brian/legacy","fcgi_bin":"/usr/sbin/fcgiwrap"}`},
		{bobSeam(), `{"kind":"static","slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":"public"}`},
	} {
		req, err := DecodeRequest([]byte(`{"action":"unit-install","spec":` + tt.spec + `}`))
		if err != nil {
			t.Fatal(err)
		}
		if resp := NewActions(loadSeam{tt.seam}).UnitInstall(req); !resp.OK {
			t.Errorf("%s: %+v", tt.spec, resp)
		}
	}
}
