package main

import (
	"os"
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
