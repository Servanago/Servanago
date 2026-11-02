// SPDX-License-Identifier: Apache-2.0

package caddywaf

import (
	"fmt"
	"testing"
)

// TestSpikeRemoveByIdOfRetiredRule pins the engine's behaviour on an exclusion naming a
// rule id the CRS does not ship (what a CRS upgrade leaves behind): SecRuleUpdateTargetById
// rejects ("rule not found"), which the wafval tests saw. Record the same for RemoveById —
// accepts = retired exclusions sit harmless; errors = the CRS bump needs a reconcile pass.
func TestSpikeRemoveByIdOfRetiredRule(t *testing.T) {
	m := &Middleware{LoadOWASPCRS: true,
		Directives: Preset + "SecRuleRemoveById 999999\n"}
	if waf, err := m.buildWAF(); err != nil {
		t.Logf("SPIKE RESULT: SecRuleRemoveById of a missing id REJECTS: %v", err)
		_ = waf
	} else {
		if c, ok := waf.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		t.Logf("SPIKE RESULT: SecRuleRemoveById of a missing id is ACCEPTED")
	}
}

func TestBuildWAFCompilesThePreset(t *testing.T) {
	m := &Middleware{LoadOWASPCRS: true, Directives: Preset}
	waf, err := m.buildWAF()
	if err != nil {
		t.Fatalf("preset does not compile: %v", err)
	}
	if c, ok := waf.(interface{ Close() error }); ok {
		if cerr := c.Close(); cerr != nil {
			t.Fatalf("close: %v", cerr)
		}
	}
}

func TestDirectivesMustCompile(t *testing.T) {
	m := &Middleware{LoadOWASPCRS: true, Directives: Preset + `SecRule ARGS "@rx (("`}
	if _, err := m.buildWAF(); err == nil {
		t.Fatal("a broken pattern compiled")
	}
}

func TestConfigKeyPoolsIdenticalConfigs(t *testing.T) {
	a := &Middleware{Directives: "SecMarker A\n", LoadOWASPCRS: true}
	b := &Middleware{Directives: "SecMarker A\n", LoadOWASPCRS: true}
	c := &Middleware{Directives: "SecMarker B\n", LoadOWASPCRS: true}
	if a.configKey() != b.configKey() {
		t.Errorf("identical configs hash apart: %s vs %s", a.configKey(), b.configKey())
	}
	if a.configKey() == c.configKey() {
		t.Errorf("different configs hash equal")
	}
}

func TestRandomStringIsConsistent(t *testing.T) {
	ids := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		id := randomString(16)
		if len(id) != 16 {
			t.Fatalf("id %q has %d characters", id, len(id))
		}
		ids[id] = struct{}{}
	}
	if len(ids) != 50 {
		t.Errorf("%d unique ids out of 50", len(ids))
	}
}

func TestMiddlewareImplementsTheCaddyContracts(t *testing.T) {
	var m Middleware
	if fmt.Sprint(m.CaddyModule().ID) == "" {
		t.Fatal("module id missing")
	}
	if m.Validate() != nil {
		t.Fatal("default validate fails")
	}
}
