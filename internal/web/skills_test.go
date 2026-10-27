package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	skillName   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	toolLike    = regexp.MustCompile("`((?:list|get|create|update|delete|set|run|plan|restore|backup|audit|runtime|unit|take|resync)_[a-z_]+)`")
	skillNeeds  = regexp.MustCompile(`(?m)^Requires ServanaGo (\d+\.\d+\.\d+) or newer\.$`)
	versionLine = regexp.MustCompile(`(?m)^Version: (\S+)$`)
)

// toolArgs are tool arguments whose names look like tools.
var toolArgs = map[string]bool{"delete_dns": true}

// frontmatter returns the name and description of a SKILL.md and its body.
func frontmatter(t *testing.T, path string) (name, desc, body string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rest, ok := strings.CutPrefix(string(b), "---\n")
	if !ok {
		t.Fatalf("%s: no frontmatter", path)
	}
	head, body, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		t.Fatalf("%s: frontmatter not closed", path)
	}
	for _, l := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(l, ":")
		switch k {
		case "name":
			name = strings.TrimSpace(v)
		case "description":
			desc = strings.TrimSpace(v)
		}
	}
	return name, desc, body
}

// The agent skills under skills/ document the MCP tools. They must not drift: every registered tool is covered by
// a skill, no skill names a tool that does not exist, and each skill states a minimum release that is not newer
// than this one. plugin.json carries the release version (see docs/RELEASING.md).
func TestAgentSkillsMatchTheMCPTools(t *testing.T) {
	s, _ := runtimeServer(t)
	s.deps.Cfg.MCPToken = mcpToken
	listed, err := mcpSession(t, s, mcpToken).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]bool{}
	for _, tl := range listed.Tools {
		tools[tl.Name] = true
	}

	ctl, err := os.ReadFile("../../packaging/DEBIAN/control")
	if err != nil {
		t.Fatal(err)
	}
	release := versionLine.FindStringSubmatch(string(ctl))[1]

	dirs, _ := filepath.Glob("../../skills/*")
	if len(dirs) < 5 {
		t.Fatalf("expected the skills under skills/, found %v", dirs)
	}
	covered := map[string]bool{}
	for _, d := range dirs {
		name, desc, body := frontmatter(t, filepath.Join(d, "SKILL.md"))
		if name != filepath.Base(d) || !skillName.MatchString(name) {
			t.Errorf("%s: name %q must equal the directory and be lowercase letters, digits and hyphens", d, name)
		}
		if len(desc) < 40 {
			t.Errorf("%s: description %q is too short to trigger on", d, desc)
		}
		need := skillNeeds.FindStringSubmatch(body)
		if need == nil {
			t.Errorf("%s: missing the line %q", d, "Requires ServanaGo X.Y.Z or newer.")
		} else if newer(need[1], release) {
			t.Errorf("%s: requires %s but this release is %s", d, need[1], release)
		}
		for _, m := range toolLike.FindAllStringSubmatch(body, -1) {
			if !tools[m[1]] && !toolArgs[m[1]] {
				t.Errorf("%s names `%s`, which is not an MCP tool", d, m[1])
			}
			covered[m[1]] = true
		}
	}
	for tl := range tools {
		if !covered[tl] {
			t.Errorf("tool %s is not covered by any skill", tl)
		}
	}

	raw, err := os.ReadFile("../../.claude-plugin/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	var plugin struct{ Name, Version, Description string }
	if err := json.Unmarshal(raw, &plugin); err != nil {
		t.Fatal(err)
	}
	if plugin.Name != "servanago" || plugin.Description == "" || plugin.Version != release {
		t.Errorf("plugin.json %+v must be named servanago, described, and at release %s", plugin, release)
	}
}

// newer reports whether version a is later than b (both X.Y.Z).
func newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range pa {
		if pa[i] != pb[i] {
			return len(pa[i]) > len(pb[i]) || (len(pa[i]) == len(pb[i]) && pa[i] > pb[i])
		}
	}
	return false
}
