package caddywaf

import (
	"strings"
	"testing"
)

func TestLoadCRS(t *testing.T) {
	rules, err := LoadCRS()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) < 400 {
		t.Fatalf("parsed %d rules, want the several hundred the CRS ships", len(rules))
	}
	byID := map[string]CRSRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	for _, want := range []string{"920320", "920420", "942100", "930120"} {
		r, ok := byID[want]
		if !ok {
			t.Fatalf("rule %s missing from the parse", want)
		}
		if r.Message == "" {
			t.Errorf("rule %s parsed without a message", want)
		}
		if r.Phase < 1 || r.Phase > 4 {
			t.Errorf("rule %s phase %d", want, r.Phase)
		}
		if r.File == "" || strings.Contains(r.File, "/") {
			t.Errorf("rule %s file %q", want, r.File)
		}
	}
	// the tags the events table displays by name come out of the parse
	got, ok := byID["942100"]
	if !ok || len(got.Tags) == 0 || !strings.Contains(strings.Join(got.Tags, ","), "attack-sqli") {
		t.Errorf("rule 942100 tags: %+v", got)
	}
	if _, ok := byID["999999"]; ok {
		t.Error("a made-up id parsed through")
	}
	// the lookup helper sees the same ids (cache path)
	if _, ok := CRSRuleByID("942100"); !ok {
		t.Error("CRSRuleByID lost a parsed rule")
	}
	if _, ok := CRSRuleByID("999999"); ok {
		t.Error("CRSRuleByID invented a rule")
	}
}

// The profile exclusions name rules the current CRS actually ships: a retired id would be
// a silent no-op and a profile that rots without anyone noticing.
func TestProfilesReferenceLiveRules(t *testing.T) {
	rules, err := LoadCRS()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.ID] = true
	}
	for name, tail := range Profiles {
		for _, line := range strings.Split(tail, "\n") {
			if !strings.HasPrefix(line, "SecRuleRemoveById ") && !strings.HasPrefix(line, "SecRuleUpdateTargetById ") {
				continue
			}
			id := strings.Fields(line)[1]
			if !ids[id] {
				t.Errorf("profile %s excludes %s, which the CRS does not ship", name, id)
			}
		}
	}
}
