package web

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/servanago/servanago/internal/store"
)

// mailMCPHarness wires the mail harness to an MCP session (open-mode server already has the CF).
func mailMCPHarness(t *testing.T, pm *pmStub) (*Server, *mcp.ClientSession) {
	t.Helper()
	s, _ := mailHarness(t, pm)
	return s, mcpSession(t, s, mcpToken)
}

func TestMCPMailListAndGet(t *testing.T) {
	s, sess := mailMCPHarness(t, newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":0,"Domains":[]}`, true))
	ctx := context.Background()
	if _, _, err := s.deps.Store.UpsertMailDomain(ctx, store.MailDomain{Name: "mail.example.com", PMServerID: 3, PMDomainID: 7,
		DKIMHost: "sel._domainkey.mail.example.com", HookPassHash: "x", DNSSetup: "one row", DKIMState: "verified"}); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Domains []mailDomainView `json:"domains"`
	}
	if err := call(t, sess, "list_mail_domains", map[string]any{}, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Domains) != 1 || list.Domains[0].HookPass != true || list.Domains[0].DNSNotes[0] != "one row" {
		t.Fatalf("list: %+v", list.Domains)
	}
	var one struct {
		Domain mailDomainView    `json:"domain"`
		Events []store.MailEvent `json:"events"`
	}
	if err := call(t, sess, "get_mail_domain", map[string]any{"name": "mail.example.com"}, &one); err != nil {
		t.Fatal(err)
	}
	if one.Domain.PMServerID != 3 {
		t.Fatalf("get: %+v", one.Domain)
	}
	// JSON must not leak the webhook hash
	b, _ := json.Marshal(list.Domains)
	if strings.Contains(string(b), "hook_pass_hash") || strings.Contains(string(b), "\"x\"") {
		t.Fatalf("hash leaked: %s", b)
	}
}

func TestMCPMailProvisionAndDelete(t *testing.T) {
	pm := newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":0,"Domains":[]}`, true)
	s, sess := mailMCPHarness(t, pm)

	err := call(t, sess, "create_mail_domain", map[string]any{"domain": "mail.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := s.deps.Store.GetMailDomain(context.Background(), "mail.example.com")
	if d.PMServerID != 500 || d.PMDomainID != 700 {
		t.Fatalf("row: %+v", d)
	}
	var push struct {
		Domain   mailDomainView `json:"domain"`
		Warnings []string       `json:"warnings"`
	}
	if err := call(t, sess, "update_mail_domain", map[string]any{"domain": "mail.example.com"}, &push); err != nil {
		t.Fatal(err)
	}
	if push.Domain.PMServerID != 500 {
		t.Fatalf("update view: %+v", push.Domain)
	}
	if err := call(t, sess, "delete_mail_domain", map[string]any{"domain": "mail.example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.deps.Store.GetMailDomain(context.Background(), "mail.example.com"); err == nil {
		t.Fatal("row must be gone")
	}
}

func TestMCPMailProvisionOwnCreds(t *testing.T) {
	pm := newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":0,"Domains":[]}`, true)
	_, sess := mailMCPHarness(t, pm)

	var prov struct {
		Domain   mailDomainView `json:"domain"`
		Warnings []string       `json:"warnings"`
	}
	err := call(t, sess, "create_mail_domain", map[string]any{"domain": "mail.example.com",
		"hook_user": "acme-hook", "hook_pass": strings.Repeat("p", 30)}, &prov)
	if err != nil {
		t.Fatal(err)
	}
	if prov.Domain.HookUser != "acme-hook" || prov.Domain.HookPass != true {
		t.Fatalf("own creds: %+v warnings %v", prov.Domain, prov.Warnings)
	}
	for _, w := range prov.Warnings { // an owned credential is never echoed
		if strings.Contains(w, strings.Repeat("p", 30)) {
			t.Fatalf("owned password echoed: %v", prov.Warnings)
		}
	}
}

func TestMCPMailEvents(t *testing.T) {
	s, sess := mailMCPHarness(t, newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":0,"Domains":[]}`, true))
	ctx := context.Background()
	did, _, err := s.deps.Store.UpsertMailDomain(ctx, store.MailDomain{Name: "mail.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.deps.Store.InsertMailEvent(ctx, store.MailEvent{DomainID: did, RecordType: "Delivery", MessageID: "m1", Payload: "{}"}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Events []store.MailEvent `json:"events"`
	}
	if err := call(t, sess, "list_mail_events", map[string]any{"domain": "mail.example.com"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 || out.Events[0].RecordType != "Delivery" {
		t.Fatalf("events: %+v", out.Events)
	}
}
