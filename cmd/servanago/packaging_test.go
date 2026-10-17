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
	for _, want := range []string{"Package: servanago", "Version: 0.1.0", "conffiles"} {
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
