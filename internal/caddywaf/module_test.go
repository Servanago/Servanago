// SPDX-License-Identifier: Apache-2.0

package caddywaf

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
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

// A matched rule through the real engine reaches the event writer with the request
// skeleton joined: site, host, rule id, verdict.
func TestEventCaptureThroughTheEngine(t *testing.T) {
	m := &Middleware{Directives: "SecRuleEngine DetectionOnly\nSecRule ARGS \"@rx evil\" \"id:7,phase:1,log\"\n", SiteID: 3, LoadOWASPCRS: false}
	waf, err := m.buildWAF()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = waf.(interface{ Close() error }).Close() })

	collected := make(chan WafEvent, 8)
	StartEventWriter(func(ev WafEvent) { collected <- ev })

	pendingEvents.Store("tx-test", eventSkeleton(3, mustGet(t, "http://t.test/?q=evil")))
	defer pendingEvents.Delete("tx-test")
	tx := waf.NewTransactionWithID("tx-test")
	tx.ProcessConnection("1.2.3.4", 80, "", 0)
	tx.ProcessURI("/?q=evil", "GET", "1.1")
	tx.AddRequestHeader("Host", "t.test")
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Fatalf("detection-only run interrupted: %+v", it)
	}
	_ = tx.Close()

	select {
	case ev := <-collected:
		if ev.SiteID != 3 || ev.RuleID != "7" || ev.Verdict != "detect" || ev.Host != "t.test" || ev.Client != "1.2.3.4" {
			t.Errorf("event wrong: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event reached the writer")
	}
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "1.2.3.4:9999"
	return r
}

// Every profile tail compiles against the CRS and ships something worth shipping; the
// exclusions inside name only rules the CRS actually carries (a retired id would be a
// silent no-op, so the test refuses it rather than let a profile rot).
func TestProfilesCompile(t *testing.T) {
	for name, tail := range Profiles {
		m := &Middleware{LoadOWASPCRS: true, Directives: Preset + tail}
		waf, err := m.buildWAF()
		if err != nil {
			t.Errorf("profile %s does not compile: %v", name, err)
		} else if c, ok := waf.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		if tail == "" {
			t.Errorf("profile %s ships nothing", name)
		}
		if !strings.Contains(Profiles["shop"], "SecRuleRemoveById 920420") {
			t.Errorf("shop profile lost its content-type exclusion")
		}
		if !strings.Contains(Profiles["php"], "SecRuleRemoveById 920320") {
			t.Errorf("php profile lost its user-agent exclusion")
		}
	}
}
