package web

import (
	"strings"
	"testing"
)

func TestMCPUpdateTools(t *testing.T) {
	r := newUpgradeRig(t, "0.18.0")
	r.deps.Cfg.MCPToken = mcpToken
	sess := mcpSession(t, r.Server, mcpToken)

	var st updateStatus
	if err := call(t, sess, "check_update", nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.Running != "0.18.0" || st.Latest != "0.19.0" || !st.Newer || !st.SchemaChange || st.Busy {
		t.Fatalf("check_update %+v", st)
	}
	if err := call(t, sess, "check_update", map[string]any{"refresh": true}, &st); err != nil || st.Latest != "0.19.0" {
		t.Fatalf("refresh: %v %+v", err, st)
	}

	for name, args := range map[string]map[string]any{
		"wrong version":   {"version": "0.20.0", "ack_breaking": true},
		"no ack":          {"version": "0.19.0"},
		"missing version": {"ack_breaking": true},
	} {
		if err := call(t, sess, "start_upgrade", args, nil); err == nil {
			t.Errorf("%s: start_upgrade must fail", name)
		}
	}
	if n := len(r.requests()); n != 0 {
		t.Fatalf("the helper was asked %d times by refused calls", n)
	}

	if err := call(t, sess, "start_upgrade", map[string]any{"version": "0.19.0", "ack_breaking": true}, nil); err != nil {
		t.Fatal(err)
	}
	got := r.requests()
	if len(got) != 1 || got[0].UpdateVersion != "0.19.0" || got[0].Actor != "mcp-token" {
		t.Fatalf("helper asked %+v", got)
	}
	found := false
	for _, e := range auditRows(t, r.Server) {
		found = found || (e.Action == "update.start" && e.Actor == "mcp token" && strings.Contains(e.Target, "0.19.0"))
	}
	if !found {
		t.Fatal("no update.start row for the MCP actor")
	}
}
