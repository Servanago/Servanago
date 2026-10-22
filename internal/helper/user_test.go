package helper

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDeriveUser(t *testing.T) {
	tests := []struct{ host, want, errHas string }{
		{"luckyedward.com", "luckyedward.com", ""},
		{"chat.tafoyaventures.com", "chat.tafoyaventures.com", ""},
		{"superlonghostname.tafoyaventures.com", "superlonghostname.tafoyaventures", ""}, // first 32 characters
		{"abcdefghijklmnopqrstuvwxyz01234.example.com", "abcdefghijklmnopqrstuvwxyz01234", ""},
		{"abcdefghijklmnopqrstuvwxyz0123.example.com", "abcdefghijklmnopqrstuvwxyz0123.e", ""}, // cut after 32; ends in a letter, so nothing to trim
		{"abcdefghijklmnopqrstuvwxyz01234-.example.com", "abcdefghijklmnopqrstuvwxyz01234", ""},
		{"123.example.com", "", "start with a letter"},
		{"-x.example.com", "", "start with a letter"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got, err := DeriveUser(tt.host)
			if tt.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errHas) {
					t.Fatalf("got %q, %v; want an error mentioning %q", got, err, tt.errHas)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestValidateUser(t *testing.T) {
	for _, ok := range []string{"bob", "luckyedward.com", "a", "my-site_2", "superlonghostname.tafoyaventures"} {
		if err := ValidateUser(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Bob", "1bob", "-bob", "bob.", "bob-", "bo b", "bo\nb", "bo/b", "bo:b", "sg-app", "servanago", "root", strings.Repeat("a", 33)} {
		if err := ValidateUser(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func bobSeam() *fakeSeam {
	seam := newFakeSeam()
	seam.userData = map[string]UserData{"bob": {Exists: true, Home: "/home/bob", Group: "bobgrp", Login: true}}
	seam.exist = map[string]bool{"/home/bob/tmp": true, "/home/bob/public_html/public": true}
	seam.exe = "/usr/bin/servanago"
	return seam
}

func TestUserCheck(t *testing.T) {
	seam := bobSeam()
	a := NewActions(seam)
	resp := a.UserCheck(req(t, ActionUserCheck, `{"user":"bob"}`))
	if !resp.OK || resp.User == nil || *resp.User != (UserData{Exists: true, Home: "/home/bob", Group: "bobgrp", Login: true}) {
		t.Fatalf("existing: %+v", resp)
	}
	resp = a.UserCheck(req(t, ActionUserCheck, `{"user":"nobody1"}`))
	if !resp.OK || resp.User == nil || resp.User.Exists {
		t.Fatalf("absent: %+v", resp)
	}
	seam.infoErr = errors.New("member of the sudo group")
	if resp := a.UserCheck(req(t, ActionUserCheck, `{"user":"bob"}`)); resp.OK || !strings.Contains(resp.Error, "sudo") {
		t.Fatalf("privileged: %+v", resp)
	}
	if resp := a.UserCheck(req(t, ActionUserCheck, `{"user":"Bad Name"}`)); resp.OK {
		t.Fatalf("bad name accepted: %+v", resp)
	}
}

func TestUserAddCreatesNamedLoginUser(t *testing.T) {
	tests := []struct {
		name, spec string
		login      bool
		dirs       []string
	}{
		{"plain", `{"slug":"lucky","user":"luckyedward.com","home":"/home/luckyedward.com","root":"/home/luckyedward.com/public_html"}`, false,
			[]string{"/home/luckyedward.com/public_html"}},
		{"shell and public", `{"slug":"lucky","user":"luckyedward.com","home":"/home/luckyedward.com","root":"/home/luckyedward.com/public_html","public":"public","shell":true}`, true,
			[]string{"/home/luckyedward.com/public_html", "/home/luckyedward.com/public_html/public"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newFakeSeam()
			resp := NewActions(seam).UserAdd(req(t, ActionUserAdd, tt.spec))
			if !resp.OK || resp.User == nil || resp.User.Login != tt.login {
				t.Fatalf("%+v", resp)
			}
			want := []createdUser{{"luckyedward.com", "/home/luckyedward.com", tt.login, tt.dirs}}
			if !reflect.DeepEqual(seam.created, want) {
				t.Errorf("created %+v, want %+v", seam.created, want)
			}
			if seam.userAdded != "" {
				t.Errorf("the generated-user path ran: %q", seam.userAdded)
			}
		})
	}
}

func TestUserAddOnExistingUserOnlyChecks(t *testing.T) {
	seam := bobSeam()
	a := NewActions(seam)
	resp := a.UserAdd(req(t, ActionUserAdd, `{"slug":"bobsite","user":"bob","root":"/home/bob/public_html"}`))
	if !resp.OK || resp.User == nil || !resp.User.Login || len(seam.created) != 0 {
		t.Fatalf("%+v created %v", resp, seam.created)
	}
	tests := []struct{ name, spec, want string }{
		{"root outside home", `{"slug":"bobsite","user":"bob","root":"/home/alice/site"}`, "inside"},
		{"root is the home", `{"slug":"bobsite","user":"bob","root":"/home/bob"}`, "inside"},
		{"sibling prefix", `{"slug":"bobsite","user":"bob","root":"/home/bobby/site"}`, "inside"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if resp := a.UserAdd(req(t, ActionUserAdd, tt.spec)); resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tt.want)
			}
		})
	}
	seam.links = map[string]string{"/home/bob/public_html": "/home/alice/site"} // a symlink out of the home
	if resp := a.UserAdd(req(t, ActionUserAdd, `{"slug":"bobsite","user":"bob","root":"/home/bob/public_html"}`)); resp.OK || !strings.Contains(resp.Error, "inside") {
		t.Fatalf("symlink escape accepted: %+v", resp)
	}
}

func TestUserAddNamedRejections(t *testing.T) {
	tests := []struct{ name, spec, want string }{
		{"home outside /home", `{"slug":"lucky","user":"lucky","home":"/etc/lucky","root":"/etc/lucky/public_html"}`, "/home or /srv"},
		{"home is /home", `{"slug":"lucky","user":"lucky","home":"/home","root":"/home/public_html"}`, "/home or /srv"},
		{"nested home", `{"slug":"lucky","user":"lucky","home":"/home/a/b","root":"/home/a/b/public_html"}`, "/home or /srv"},
		{"home missing", `{"slug":"lucky","user":"lucky","root":"/home/lucky/public_html"}`, "home"},
		{"root outside home", `{"slug":"lucky","user":"lucky","home":"/home/lucky","root":"/srv/other"}`, "inside"},
		{"reserved prefix", `{"slug":"lucky","user":"sg-lucky","home":"/home/sg-lucky","root":"/home/sg-lucky/public_html"}`, "reserved"},
		{"bad public", `{"slug":"lucky","user":"lucky","home":"/home/lucky","root":"/home/lucky/public_html","public":"../x"}`, "public"},
		{"newline in home", "{\"slug\":\"lucky\",\"user\":\"lucky\",\"home\":\"/home/lucky\\nUser=root\",\"root\":\"/home/lucky/public_html\"}", "home"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := newFakeSeam()
			resp := NewActions(seam).UserAdd(req(t, ActionUserAdd, tt.spec))
			if resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tt.want)
			}
			if len(seam.created) != 0 {
				t.Errorf("a user was created: %v", seam.created)
			}
		})
	}
}

func TestUnitInstallRunsAsTheNamedUser(t *testing.T) {
	base := `"slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":"public"`
	tests := []struct {
		name, spec string
	}{
		{"node", `{"kind":"node",` + strings.Replace(base, `,"public":"public"`, "", 1) + `,"port":3000,"start":"node server.js"}`},
		{"frankenphp", `{"kind":"frankenphp",` + base + `,"port":8100,"franken_bin":"/usr/local/bin/frankenphp"}`},
		{"cgi", `{"kind":"cgi",` + strings.Replace(base, `,"public":"public"`, "", 1) + `,"fcgi_bin":"/usr/sbin/fcgiwrap"}`},
		{"php", `{"kind":"php",` + base + `,"fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`},
		{"static", `{"kind":"static",` + base + `}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := bobSeam()
			resp := NewActions(seam).UnitInstall(req(t, ActionUnitInstall, tt.spec))
			if !resp.OK {
				t.Fatalf("%+v", resp)
			}
			u := string(seam.written["/etc/systemd/system/servanago-bobsite.service"])
			// The unit may write the site folder and the home's tmp (it exists), not the home's logs (it does not).
			if tt.name != "php" && tt.name != "static" && !strings.Contains(u, "ReadWritePaths=/home/bob/public_html /home/bob/tmp\n") {
				t.Errorf("writable paths wrong:\n%s", u)
			}
			if strings.Contains(u, "/home/bob/logs") {
				t.Errorf("a missing logs directory was listed:\n%s", u)
			}
			switch tt.name {
			case "php":
				if strings.Contains(u, "\nUser=") || !strings.Contains(u, "/home/bob/public_html /home/bob/tmp") {
					t.Errorf("php master runs as root, workers via the pool:\n%s", u)
				}
				pool := string(seam.written["/etc/servanago/fpm/bobsite.conf"])
				for _, want := range []string{"user=bob\n", "group=bobgrp\n"} {
					if !strings.Contains(pool, want) {
						t.Errorf("pool missing %q:\n%s", want, pool)
					}
				}
			case "frankenphp":
				if !strings.Contains(u, "User=bob\nGroup=bobgrp\n") || !strings.Contains(u, "php-server --root /home/bob/public_html/public --listen") ||
					!strings.Contains(u, "WorkingDirectory=/home/bob/public_html\n") {
					t.Errorf("frankenphp unit:\n%s", u)
				}
			case "static":
				if !strings.Contains(u, "User=bob\nGroup=bobgrp\n") || !strings.Contains(u, "ExecStart=/usr/bin/servanago serve-static --root /home/bob/public_html/public\n") ||
					!strings.Contains(u, "Requires=servanago-bobsite.socket") || strings.Contains(u, "[Install]") {
					t.Errorf("static unit:\n%s", u)
				}
				sock := string(seam.written["/etc/systemd/system/servanago-bobsite.socket"])
				if !strings.Contains(sock, "ListenStream=/run/servanago/bobsite.sock") || seam.enabled != "servanago-bobsite.socket" {
					t.Errorf("static socket:\n%s enabled=%q", sock, seam.enabled)
				}
			default:
				if !strings.Contains(u, "User=bob\nGroup=bobgrp\n") || !strings.Contains(u, "WorkingDirectory=/home/bob/public_html\n") {
					t.Errorf("%s unit:\n%s", tt.name, u)
				}
			}
		})
	}
}

func TestUnitInstallNamedUserRejections(t *testing.T) {
	tests := []struct {
		name, spec string
		prep       func(*fakeSeam)
		want       string
	}{
		{"user missing", `{"kind":"node","slug":"bobsite","user":"ghost","root":"/home/ghost/app","port":3000,"start":"x"}`, nil, "does not exist"},
		{"root outside the home", `{"kind":"node","slug":"bobsite","user":"bob","root":"/srv/app","port":3000,"start":"x"}`, nil, "inside"},
		{"privileged user", `{"kind":"node","slug":"bobsite","user":"bob","root":"/home/bob/app","port":3000,"start":"x"}`, func(s *fakeSeam) { s.infoErr = errors.New("member of the sudo group") }, "sudo"},
		{"public with ..", `{"kind":"php","slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":"../etc","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`, nil, "public"},
		{"public absolute", `{"kind":"php","slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":"/etc","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`, nil, "public"},
		{"public dotdir", `{"kind":"php","slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":".git","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`, nil, "public"},
		{"public missing", `{"kind":"php","slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":"nope","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`, nil, "does not exist"},
		{"public escapes by symlink", `{"kind":"php","slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":"public","fpm_bin":"/usr/sbin/php-fpm8.2","fpm_version":"8.2"}`,
			func(s *fakeSeam) { s.links = map[string]string{"/home/bob/public_html/public": "/etc"} }, "public"},
		{"public on node", `{"kind":"node","slug":"bobsite","user":"bob","root":"/home/bob/public_html","public":"public","port":3000,"start":"x"}`, nil, "public"},
		{"static without a user", `{"kind":"static","slug":"bobsite","root":"/srv/site"}`, nil, "user"},
		{"static without the helper exe", `{"kind":"static","slug":"bobsite","user":"bob","root":"/home/bob/public_html"}`, func(s *fakeSeam) { s.exe = "" }, "executable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seam := bobSeam()
			if tt.prep != nil {
				tt.prep(seam)
			}
			resp := NewActions(seam).UnitInstall(req(t, ActionUnitInstall, tt.spec))
			if resp.OK || !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tt.want)
			}
			if len(seam.written) != 0 {
				t.Errorf("host was written: %v", keys(seam.written))
			}
		})
	}
}

// A generated-user site may have a public folder too.
func TestPublicFolderOnGeneratedUser(t *testing.T) {
	seam := newFakeSeam()
	seam.exist = map[string]bool{"/srv/blog/public": true}
	resp := NewActions(seam).UnitInstall(req(t, ActionUnitInstall, `{"kind":"frankenphp","slug":"blog","root":"/srv/blog","public":"public","port":8100,"franken_bin":"/usr/local/bin/frankenphp"}`))
	u := string(seam.written["/etc/systemd/system/servanago-blog.service"])
	if !resp.OK || !strings.Contains(u, "User=sg-blog\nGroup=sg-blog\n") || !strings.Contains(u, "--root /srv/blog/public ") || !strings.Contains(u, "ReadWritePaths=/srv/blog\n") {
		t.Fatalf("%+v\n%s", resp, u)
	}
}

func TestPHPUserDefaultCarriesTheSiteINI(t *testing.T) {
	seam := newPHPSeam()
	a := NewActions(seam)
	if resp := a.PHPUserDefault(req(t, ActionPHPUserDefault, `{"user":"luckyedward.com","php_version":"8.4","slug":"lucky"}`)); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if got := string(seam.written["/etc/servanago/php-users/luckyedward.com"]); got != "8.4\n/etc/servanago/php/lucky.ini\n" {
		t.Errorf("mapping %q", got)
	}
	if resp := a.PHPUserDefault(req(t, ActionPHPUserDefault, `{"user":"brian","php_version":"8.4","slug":"../x"}`)); resp.OK {
		t.Errorf("bad slug accepted: %+v", resp)
	}
}
