package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSystemdUnit covers the unit contract: unprivileged with only the bind capability,
// config from the packaged env file, restart on failure — and never ProtectHome=yes,
// because static site roots may live under /home (M2 decision).
func TestSystemdUnit(t *testing.T) {
	b, err := os.ReadFile("../../packaging/servanago.service")
	if err != nil {
		t.Fatal(err)
	}
	u := string(b)
	for _, want := range []string{
		"[Unit]", "After=network-online.target",
		"User=servanago", "Group=servanago",
		"ExecStart=/usr/bin/servanago",
		"EnvironmentFile=-/etc/servanago/servanago.env",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"Restart=on-failure",
		"WantedBy=multi-user.target",
		`ReadWritePaths=/var/lib/servanago /var/log/servanago`,
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q", want)
		}
	}
	if strings.Contains(u, "ProtectHome=yes") {
		t.Error("unit must not set ProtectHome=yes: static roots may live under /home")
	}
}

// The helper daemon unit: root process, socket dir group-visible to the control plane.
func TestHelperSystemdUnit(t *testing.T) {
	b, err := os.ReadFile("../../packaging/servanago-helper.service")
	if err != nil {
		t.Fatal(err)
	}
	u := string(b)
	for _, want := range []string{
		"ExecStart=/usr/bin/servanago helper",
		"RuntimeDirectory=servanago",
		"RuntimeDirectoryMode=0755",
		"RuntimeDirectoryPreserve=yes", // site sockets live here: a helper restart must not delete them
		"Restart=on-failure",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("helper unit missing %q", want)
		}
	}
}

// The installed env file is a copy of .env.example; the admin edits it as a conffile.
func TestEnvTemplateMatchesExample(t *testing.T) {
	ex, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := os.ReadFile("../../packaging/servanago.env")
	if err != nil {
		t.Fatal(err)
	}
	if string(ex) != string(tpl) {
		t.Error("packaging/servanago.env must be a copy of .env.example")
	}
}

// TestBuildDeb assembles and builds the deb with a stub binary, then checks its contents
// with dpkg-deb. Skip: a non-debian build host has no dpkg-deb.
func TestBuildDeb(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("no dpkg-deb on this host")
	}
	// The script runs with the repo root as its working directory.
	stub := filepath.Join(t.TempDir(), "servanago")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "servanago.deb")
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("../../packaging/build-deb.sh", stub, out)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build-deb.sh: %v\n%s%s", err, stdout.String(), stderr.String())
	}
	info, err := exec.Command("dpkg-deb", "--info", out).Output()
	if err != nil {
		t.Fatalf("dpkg-deb --info: %v", err)
	}
	for _, want := range []string{"Package: servanago", "Version: 0.6.1", "conffiles"} {
		if !strings.Contains(string(info), want) {
			t.Errorf("deb info missing %q:\n%s", want, info)
		}
	}
	list, err := exec.Command("dpkg-deb", "-c", out).Output()
	if err != nil {
		t.Fatalf("dpkg-deb -c: %v", err)
	}
	for _, want := range []string{"usr/bin/servanago", "lib/systemd/system/servanago.service", "etc/servanago/servanago.env"} {
		if !strings.Contains(string(list), want) {
			t.Errorf("deb missing %q:\n%s", want, list)
		}
	}
}

// install.sh must parse and refuse to run without root (it does nothing but the id check first).
func TestInstallScript(t *testing.T) {
	if err := exec.Command("bash", "-n", "../../packaging/install.sh").Run(); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd := exec.Command("bash", "../../packaging/install.sh")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Error("install.sh ran without root; want refusal")
	} else if !strings.Contains(stderr.String(), "root") {
		t.Errorf("refusal %q does not mention root", stderr.String())
	}
}

// runMaintainer runs a packaging/DEBIAN script with stubbed system tools and returns the systemctl calls.
// active names the units `systemctl is-active` reports as running.
func runMaintainer(t *testing.T, runDir, script, active string, args ...string) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "systemctl.log")
	stubs := map[string]string{
		"systemctl": "echo \"$*\" >> " + log + "\n" +
			"if [ \"$1\" = is-active ]; then case \" $FAKE_ACTIVE \" in *\" $3 \"*) exit 0;; esac; exit 3; fi\n",
		"id": "exit 0", "install": "exit 0", "chown": "exit 0", "chmod": "exit 0", "useradd": "exit 0",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", append([]string{"../../packaging/DEBIAN/" + script}, args...)...)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "SERVANAGO_RUN_DIR="+runDir, "FAKE_ACTIVE="+active)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", script, args, err, out)
	}
	b, _ := os.ReadFile(log)
	return string(b)
}

// An upgrade stops both units in prerm; postinst must start again the ones that were running, helper first.
func TestUpgradeRestartsRunningUnits(t *testing.T) {
	run := t.TempDir()
	const both = "servanago.service servanago-helper.service"
	runMaintainer(t, run, "prerm", both, "upgrade")
	got := runMaintainer(t, run, "postinst", "", "configure", "0.2.0")
	h, w := strings.Index(got, "start servanago-helper.service"), strings.Index(got, "start servanago.service")
	if h < 0 || w < 0 || h > w {
		t.Errorf("want helper started before the web service, got:\n%s", got)
	}
}

// A unit the admin had stopped stays stopped across an upgrade, and a first install starts nothing.
func TestUpgradeLeavesStoppedUnitsAlone(t *testing.T) {
	run := t.TempDir()
	runMaintainer(t, run, "prerm", "servanago-helper.service", "upgrade") // the web service was not running
	got := runMaintainer(t, run, "postinst", "", "configure", "0.2.0")
	if strings.Contains(got, "start servanago.service") || !strings.Contains(got, "start servanago-helper.service") {
		t.Errorf("only the helper was running:\n%s", got)
	}
	fresh := runMaintainer(t, t.TempDir(), "postinst", "", "configure")
	if strings.Contains(fresh, " start ") || strings.HasPrefix(fresh, "start ") {
		t.Errorf("a first install must not start anything:\n%s", fresh)
	}
}
