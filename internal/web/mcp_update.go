package web

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/servanago/servanago/internal/update"
)

// mcp_update.go: the update tools. They call the same code as the Updates page; the page's password is replaced by the
// MCP token, as for every other write tool, and `version` must name the release the check found.

type updateStatus struct {
	Running      string `json:"running"`
	Latest       string `json:"latest,omitempty"`
	Newer        bool   `json:"newer"`
	NotesURL     string `json:"notes_url,omitempty"`
	SchemaChange bool   `json:"schema_change,omitempty"`
	Breaking     bool   `json:"breaking,omitempty"`
	CheckedAt    int64  `json:"checked_at,omitempty"`
	Busy         bool   `json:"busy"`
	Phase        string `json:"phase,omitempty"`
	LastResult   string `json:"last_result,omitempty"` // completed | rolledback | needs_hands | failed
	LastError    string `json:"last_error,omitempty"`
}

func (s *Server) updateStatus(ctx context.Context) updateStatus {
	res, at := s.loadUpdate(ctx)
	st := updateStatus{Running: s.runningVersion(), Latest: res.Manifest.Version, NotesURL: res.Manifest.NotesURL,
		SchemaChange: res.Manifest.SchemaChange, Breaking: res.Manifest.Breaking, CheckedAt: at}
	st.Newer = update.Newer(st.Running, st.Latest)
	state, busy := s.upgradeState()
	st.Busy = busy
	if busy {
		st.Phase = state.Phase
	}
	if last, ok := s.lastUpgrade(); ok {
		switch {
		case last.OK:
			st.LastResult = "completed"
		case last.NeedsHands:
			st.LastResult = "needs_hands"
		case last.RolledBack:
			st.LastResult = "rolledback"
		default:
			st.LastResult = "failed"
		}
		st.LastError = last.Error
	}
	return st
}

func (s *Server) addUpdateTools(srv *mcp.Server, ip string, ro *mcp.ToolAnnotations) {
	mcp.AddTool(srv, &mcp.Tool{Name: "check_update", Description: "The running ServanaGo version, the latest signed release the weekly check found, whether it is newer, whether it changes the database or is breaking, and the last upgrade's outcome. refresh=true looks at GitHub now.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Refresh bool `json:"refresh,omitempty" jsonschema:"fetch the release manifest now instead of using the last check"`
		}) (*mcp.CallToolResult, updateStatus, error) {
			if in.Refresh {
				if err := s.runUpdateCheck(ctx); err != nil {
					return nil, updateStatus{}, err
				}
			}
			return nil, s.updateStatus(ctx), nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "start_upgrade", Description: "Install the latest release: the root job downloads the signed package, copies the database, installs it, checks the panel and rolls back on failure. The panel restarts; poll check_update (busy, last_result). version must be the latest release from check_update; ack_breaking must be true when it changes the database or is breaking. Never start one without the admin's say-so."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Version     string `json:"version" jsonschema:"the latest release, from check_update"`
			AckBreaking bool   `json:"ack_breaking,omitempty" jsonschema:"required when check_update says schema_change or breaking"`
		}) (*mcp.CallToolResult, struct {
			Started string `json:"started"`
		}, error) {
			none := struct {
				Started string `json:"started"`
			}{}
			if code, err := s.startUpgrade(ctx, in.Version, in.AckBreaking, "mcp-token"); err != nil {
				return nil, none, fmt.Errorf("%d: %w", code, err)
			}
			r := withUser(httptest.NewRequestWithContext(ctx, "POST", "/updates/upgrade", nil), mcpActor)
			r.RemoteAddr = net.JoinHostPort(ip, "0")
			s.audit(r, "update.start", in.Version)
			return nil, struct {
				Started string `json:"started"`
			}{in.Version}, nil
		})
}
