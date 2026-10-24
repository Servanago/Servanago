package web

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/servanago/servanago/internal/backup"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/store"
)

// mcp_backup.go: the backup tools. They call the same code as the Backups page. The panel is never restored here:
// that is `servanago backup restore --panel` on the server.

type backupRunOut struct {
	Scope    string `json:"scope"`
	Trigger  string `json:"trigger"`
	Status   string `json:"status"`
	Archive  string `json:"archive,omitempty"`
	Error    string `json:"error,omitempty"`
	Finished string `json:"finished"`
}

func runOut(r store.BackupRun) backupRunOut {
	e := r.Error
	if len(e) > 300 {
		e = e[:300]
	}
	return backupRunOut{Scope: r.Scope, Trigger: r.Trigger, Status: r.Status, Archive: r.Archive, Error: e, Finished: when(r.Finished)}
}

// scopeSite resolves a scope argument ("panel" or a site slug) to its site, if any.
func (s *Server) scopeSite(ctx context.Context, scope string) (store.Site, bool) {
	sites, _ := s.deps.Store.ListSites(ctx)
	for _, x := range sites {
		if x.Slug == scope {
			return x, true
		}
	}
	return store.Site{}, false
}

func (s *Server) addBackupTools(srv *mcp.Server, ip string, ro *mcp.ToolAnnotations) {
	siteByID := func(ctx context.Context, id int64) (store.Site, error) {
		x, err := s.deps.Store.GetSite(ctx, id)
		if err != nil {
			return x, fmt.Errorf("site %d not found", id)
		}
		return x, nil
	}

	mcp.AddTool(srv, &mcp.Tool{Name: "backup_status", Description: "Backup settings (no passphrase, no ntfy address), whether the job is running, the stale/failed warning and the latest result per scope.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct {
			Enabled       bool           `json:"enabled"`
			Panel         bool           `json:"panel"`
			Folder        string         `json:"folder"`
			Schedule      string         `json:"schedule"`
			Keep          int            `json:"keep"`
			KeepWeekly    int            `json:"keep_weekly"`
			PassphraseSet bool           `json:"passphrase_set"`
			NtfySet       bool           `json:"ntfy_set"`
			JobState      string         `json:"job_state,omitempty"`
			Warning       string         `json:"warning,omitempty"`
			Last          []backupRunOut `json:"last"`
		}, error) {
			var out struct {
				Enabled       bool           `json:"enabled"`
				Panel         bool           `json:"panel"`
				Folder        string         `json:"folder"`
				Schedule      string         `json:"schedule"`
				Keep          int            `json:"keep"`
				KeepWeekly    int            `json:"keep_weekly"`
				PassphraseSet bool           `json:"passphrase_set"`
				NtfySet       bool           `json:"ntfy_set"`
				JobState      string         `json:"job_state,omitempty"`
				Warning       string         `json:"warning,omitempty"`
				Last          []backupRunOut `json:"last"`
			}
			set, err := s.deps.Store.GetBackupSettings(ctx)
			if err != nil {
				return nil, out, err
			}
			out.Enabled, out.Panel, out.Folder, out.Schedule, out.Keep, out.KeepWeekly = set.Enabled, set.Panel, set.Dir, set.Sched, set.Keep, set.KeepWeekly
			out.PassphraseSet, out.NtfySet, out.Warning, out.Last = set.Pass != nil, set.Ntfy != nil, s.backupWarnText(), []backupRunOut{}
			if resp, err := s.helperClient().Call(ctx, helper.ActionBackupStatus, helper.Spec{}); err == nil && resp.Status != nil {
				out.JobState = resp.Status.ActiveState
			}
			last, _, err := s.deps.Store.LastRuns(ctx)
			for _, r := range last {
				out.Last = append(out.Last, runOut(r))
			}
			slices.SortFunc(out.Last, func(a, b backupRunOut) int { return strings.Compare(a.Scope, b.Scope) })
			return nil, out, err
		})

	type archiveOut struct {
		Scope   string   `json:"scope"`
		Name    string   `json:"name"`
		Started string   `json:"started"`
		Bytes   int64    `json:"bytes"`
		Trigger string   `json:"trigger"`
		Dumps   []string `json:"dumps,omitempty"`
		Volumes []string `json:"volumes,omitempty"`
		Damaged string   `json:"damaged,omitempty"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "list_backups", Description: "Archives (newest first) and recent runs. scope: panel or a site's short name (slug); leave out for all.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Scope string `json:"scope,omitempty"`
		}) (*mcp.CallToolResult, struct {
			Archives []archiveOut   `json:"archives"`
			Runs     []backupRunOut `json:"runs"`
		}, error) {
			out := struct {
				Archives []archiveOut   `json:"archives"`
				Runs     []backupRunOut `json:"runs"`
			}{Archives: []archiveOut{}, Runs: []backupRunOut{}}
			set, err := s.deps.Store.GetBackupSettings(ctx)
			if err != nil {
				return nil, out, err
			}
			scopes := []string{in.Scope}
			if in.Scope == "" {
				scopes = []string{"panel"}
				sites, _ := s.deps.Store.ListSites(ctx)
				for _, x := range sites {
					scopes = append(scopes, x.Slug)
				}
			} else if _, ok := s.scopeSite(ctx, in.Scope); !ok && in.Scope != "panel" {
				return nil, out, fmt.Errorf("unknown scope %q: use panel or a site's short name", in.Scope)
			}
			for _, sc := range scopes {
				ins, err := backup.List(set.Dir, sc)
				if err != nil {
					return nil, out, err
				}
				for _, a := range ins {
					out.Archives = append(out.Archives, archiveOut{Scope: sc, Name: a.Name, Started: a.Manifest.Started.Local().Format("2006-01-02 15:04"), Bytes: a.Bytes,
						Trigger: a.Manifest.Trigger, Dumps: a.Manifest.Profiles, Volumes: a.Manifest.Volumes, Damaged: a.Damaged})
				}
			}
			runs, err := s.deps.Store.ListRuns(ctx, in.Scope, 20)
			for _, r := range runs {
				out.Runs = append(out.Runs, runOut(r))
			}
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "run_backup", Description: "Start a backup now: scope all, panel, or a site's short name. The result shows up in backup_status and list_backups within a minute of the job ending."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Scope string `json:"scope" jsonschema:"all | panel | a site's short name"`
		}) (*mcp.CallToolResult, struct {
			Started string `json:"started"`
		}, error) {
			form := url.Values{"scope": {in.Scope}}
			if in.Scope != "all" && in.Scope != "panel" {
				x, ok := s.scopeSite(ctx, in.Scope)
				if !ok {
					return nil, struct {
						Started string `json:"started"`
					}{}, fmt.Errorf("unknown scope %q: use all, panel or a site's short name", in.Scope)
				}
				form = url.Values{"scope": {"site"}, "site": {strconv.FormatInt(x.ID, 10)}}
			}
			_, err := s.mcpRun(ctx, ip, s.runBackup, "POST", "/backups/run", 0, form)
			return nil, struct {
				Started string `json:"started"`
			}{in.Scope}, err
		})

	type volumePlan struct {
		Name       string `json:"name"`
		Restorable bool   `json:"restorable"`
		Containers string `json:"containers"`
	}
	type planOut struct {
		Site    string       `json:"site"`
		Archive string       `json:"archive"`
		Files   bool         `json:"files"`
		Dumps   []string     `json:"dumps"`
		Volumes []volumePlan `json:"volumes"`
		Warning string       `json:"warning"`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "plan_restore", Description: "What restore_site would do with an archive: what it holds, which volumes can be restored, and which containers a volume restore stops and starts again.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			ID      int64  `json:"id"`
			Archive string `json:"archive"`
		}) (*mcp.CallToolResult, planOut, error) {
			x, err := siteByID(ctx, in.ID)
			if err != nil {
				return nil, planOut{}, err
			}
			a, err := s.scopeInfo(ctx, x.Slug, in.Archive)
			if err != nil {
				return nil, planOut{}, err
			}
			out := planOut{Site: x.Slug, Archive: a.Name, Dumps: a.Manifest.Profiles, Volumes: []volumePlan{},
				Warning: "A restore overwrites files, databases and volumes. A backup of the current state is taken first."}
			for _, p := range a.Manifest.Parts {
				out.Files = out.Files || p.Kind == "files"
			}
			on, _ := s.deps.Store.ListVolumes(ctx, x.ID)
			users := s.volumeUsers(ctx, a.Manifest.Volumes)
			for _, v := range a.Manifest.Volumes {
				out.Volumes = append(out.Volumes, volumePlan{Name: v, Restorable: slices.Contains(on, v), Containers: users[v]})
			}
			return nil, out, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "restore_site", Description: "Restore a site from one of its archives: files, database dumps and/or volumes. Overwrites them (a backup of the current state is taken first); a volume restore stops the containers that use it and starts them again. confirm must be the site's short name. Run plan_restore first."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			ID      int64    `json:"id"`
			Archive string   `json:"archive"`
			Files   bool     `json:"files,omitempty"`
			Dumps   bool     `json:"dumps,omitempty"`
			Volumes []string `json:"volumes,omitempty"`
			Confirm string   `json:"confirm" jsonschema:"the site's short name, exactly"`
		}) (*mcp.CallToolResult, struct {
			Started string `json:"started"`
		}, error) {
			none := struct {
				Started string `json:"started"`
			}{}
			x, err := siteByID(ctx, in.ID)
			if err != nil {
				return nil, none, err
			}
			if in.Confirm != x.Slug {
				return nil, none, fmt.Errorf("confirm must be the site's short name (%s): a restore overwrites files, databases and volumes", x.Slug)
			}
			spec, serr := s.checkRestore(ctx, x, in.Archive, in.Files, in.Dumps, in.Volumes)
			if serr != nil {
				return nil, none, fmt.Errorf("%s", serr.msg)
			}
			r := withUser(httptest.NewRequestWithContext(ctx, "POST", "/backups/restore", nil), mcpActor)
			r.RemoteAddr = net.JoinHostPort(ip, "0")
			serr = s.sendRestore(r, x, spec)
			s.takeFlashes()
			if serr != nil {
				return nil, none, fmt.Errorf("%s", serr.msg)
			}
			return nil, struct {
				Started string `json:"started"`
			}{x.Slug + " " + in.Archive}, nil
		})
}
