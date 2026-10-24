package web

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

func TestMCPBackupTools(t *testing.T) {
	b := backupServer(t)
	b.s.deps.Cfg.MCPToken = mcpToken
	if w := b.settings(); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	site := b.site(t, "shop.example.com")
	ctx := context.Background()
	_ = b.s.deps.Store.AddVolume(ctx, site.ID, "data")
	arch := b.archiveWithVolumes(t, site.Slug, "data")
	sess := mcpSession(t, b.s, mcpToken)

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	panelRestore := regexp.MustCompile(`panel.*restore|restore.*panel`)
	for _, tl := range tools.Tools {
		have[tl.Name] = true
		if panelRestore.MatchString(tl.Name) {
			t.Errorf("tool %s restores the panel: that is CLI only", tl.Name)
		}
	}
	for _, want := range []string{"backup_status", "list_backups", "run_backup", "plan_restore", "restore_site"} {
		if !have[want] {
			t.Errorf("tool %s missing", want)
		}
	}

	var st struct {
		Enabled       bool   `json:"enabled"`
		PassphraseSet bool   `json:"passphrase_set"`
		Folder        string `json:"folder"`
	}
	if err := call(t, sess, "backup_status", nil, &st); err != nil || !st.Enabled || !st.PassphraseSet || st.Folder != b.dir {
		t.Fatalf("backup_status %+v %v", st, err)
	}

	var lb struct {
		Archives []struct {
			Scope, Name string
			Volumes     []string
		} `json:"archives"`
	}
	if err := call(t, sess, "list_backups", map[string]any{"scope": site.Slug}, &lb); err != nil || len(lb.Archives) != 1 || lb.Archives[0].Name != arch || lb.Archives[0].Volumes[0] != "data" {
		t.Fatalf("list_backups %+v %v", lb, err)
	}

	if err := call(t, sess, "run_backup", map[string]any{"scope": "nonsense"}, nil); err == nil {
		t.Error("an unknown scope was accepted")
	}
	if err := call(t, sess, "run_backup", map[string]any{"scope": site.Slug}, nil); err != nil {
		t.Fatalf("run_backup: %v", err)
	}
	if got := b.host.log(); !strings.Contains(got, "backup-start scope=site slug="+site.Slug) {
		t.Errorf("helper calls: %s", got)
	}

	var plan struct {
		Volumes []struct {
			Name       string `json:"name"`
			Restorable bool   `json:"restorable"`
			Containers string `json:"containers"`
		} `json:"volumes"`
	}
	if err := call(t, sess, "plan_restore", map[string]any{"id": site.ID, "archive": arch}, &plan); err != nil || len(plan.Volumes) != 1 || !plan.Volumes[0].Restorable || plan.Volumes[0].Containers == "" {
		t.Fatalf("plan_restore %+v %v", plan, err)
	}

	args := map[string]any{"id": site.ID, "archive": arch, "volumes": []string{"data"}}
	for name, a := range map[string]map[string]any{
		"no confirm":      args,
		"wrong confirm":   {"id": site.ID, "archive": arch, "volumes": []string{"data"}, "confirm": site.Slug + "x"},
		"nothing chosen":  {"id": site.ID, "archive": arch, "confirm": site.Slug},
		"volume not in":   {"id": site.ID, "archive": arch, "volumes": []string{"other"}, "confirm": site.Slug},
		"another archive": {"id": site.ID, "archive": "blog-20260101T000000Z.tar.zst.age", "volumes": []string{"data"}, "confirm": site.Slug},
	} {
		if err := call(t, sess, "restore_site", a, nil); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if strings.Contains(b.host.log(), "backup-restore") {
		t.Fatalf("a refused restore reached the helper: %s", b.host.log())
	}
	args["confirm"] = site.Slug
	if err := call(t, sess, "restore_site", args, nil); err != nil {
		t.Fatalf("restore_site: %v", err)
	}
	if got := b.host.log(); !strings.Contains(got, "backup-restore") || !strings.Contains(got, "volumes=[data]") || !strings.Contains(got, "actor=mcp-token") { // the helper's actor pattern has no space
		t.Errorf("helper calls: %s", got)
	}
	rows, _ := b.s.deps.Store.ListAudit(ctx, 10)
	var found bool
	for _, r := range rows {
		found = found || r.Action == "backup.restore" && r.Actor == "mcp token"
	}
	if !found {
		t.Errorf("no audit row by the token: %+v", rows)
	}
}
