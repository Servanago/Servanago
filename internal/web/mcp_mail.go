// Mail-bridge MCP tools: reads go to the store, mutations reuse the UI's provision/remove
// handlers through mcpRun (audited as 'mcp token'). The webhook password is write-input only.
package web

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/servanago/servanago/internal/store"
)

// mailDomainView is one provisioned mail domain for MCP; the webhook password never leaves.
type mailDomainView struct {
	Name        string   `json:"name"`
	PMServerID  int64    `json:"postmark_server_id,omitempty"`
	PMDomainID  int64    `json:"postmark_domain_id,omitempty"`
	DKIMHost    string   `json:"dkim_host,omitempty"`
	DKIMText    string   `json:"dkim_text,omitempty"`
	ReturnPath  string   `json:"return_path,omitempty"`
	HookUser    string   `json:"hook_user,omitempty"`
	HookPass    bool     `json:"hook_password_set,omitempty"`
	DNSNotes    []string `json:"dns_notes,omitempty"`
	DKIMState   string   `json:"dkim_state,omitempty"`
	RPState     string   `json:"return_path_state,omitempty"`
	LastVerify  int64    `json:"last_verify,omitempty"`
	LMTPAddr    string   `json:"lmtp_addr,omitempty"`
	HookPath    string   `json:"hook_path,omitempty"`
	EventsPath  string   `json:"events_path,omitempty"`
	Recv        int      `json:"received,omitempty"`
	Delivered   int      `json:"delivered,omitempty"`
	Deduped     int      `json:"deduped,omitempty"`
	Rejected    int      `json:"rejected,omitempty"`
	Fallbacks   int      `json:"rebuilt,omitempty"`
	LastInbound int64    `json:"last_inbound,omitempty"`
}

// provisioned is what a provisioning tool answers: the row and the shown-once warnings.
type provisioned struct {
	Domain   mailDomainView `json:"domain"`
	Warnings []string       `json:"warnings,omitempty"`
}

func mailViewOf(md store.MailDomain) mailDomainView {
	return mailDomainView{
		Name: md.Name, PMServerID: md.PMServerID, PMDomainID: md.PMDomainID,
		DKIMHost: md.DKIMHost, DKIMText: md.DKIMText, ReturnPath: md.ReturnPath,
		HookUser: md.HookUser, HookPass: md.HookPassHash != "", DNSNotes: linesOf(md.DNSSetup),
		DKIMState: md.DKIMState, RPState: md.RPState, LastVerify: md.LastVerify, LMTPAddr: md.LMTPAddr,
		HookPath: "/_mailbridge/hook/" + md.Name, EventsPath: "/_mailbridge/events/" + md.Name,
		Recv: md.Recv, Delivered: md.Delivered, Deduped: md.Deduped, Rejected: md.Rejected,
		Fallbacks: md.Fallbacks, LastInbound: md.LastInbound,
	}
}

// linesOf splits a notes block into its lines for JSON output.
func linesOf(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func (s *Server) addMailTools(srv *mcp.Server, ip string, ro *mcp.ToolAnnotations) {
	mcp.AddTool(srv, &mcp.Tool{Name: "list_mail_domains", Description: "Provisioned mail domains: Postmark ids, verification states, DNS notes and inbound counters. No webhook secrets.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, struct {
			Domains []mailDomainView `json:"domains"`
		}, error) {
			var out struct {
				Domains []mailDomainView `json:"domains"`
			}
			rows, err := s.deps.Store.ListMailDomains(ctx)
			for _, md := range rows {
				out.Domains = append(out.Domains, mailViewOf(md))
			}
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "get_mail_domain", Description: "One mail domain with its states, notes and counters, plus its most recent events.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Name   string `json:"name" jsonschema:"the mail domain's FQDN, from list_mail_domains"`
			Events int    `json:"events,omitempty"`
		}) (*mcp.CallToolResult, struct {
			Domain mailDomainView    `json:"domain"`
			Events []store.MailEvent `json:"events,omitempty"`
		}, error) {
			var out struct {
				Domain mailDomainView    `json:"domain"`
				Events []store.MailEvent `json:"events,omitempty"`
			}
			md, err := s.deps.Store.GetMailDomain(ctx, in.Name)
			if err != nil {
				return nil, out, fmt.Errorf("mail domain %q is not provisioned", strings.ToLower(in.Name))
			}
			out.Domain = mailViewOf(md)
			if in.Events <= 0 || in.Events > 100 {
				in.Events = 10
			}
			out.Events, err = s.deps.Store.ListMailEvents(ctx, md.ID, in.Events)
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "create_mail_domain", Description: "Provision a mail domain: Postmark server mail-DOMAIN + domain, webhook URLs and credential, then detached DNS rows (never deletes; foreign SPF untouched), InboundDomain and verification watch. Stops naming what exists unless adopt. Audited as 'mcp token'. The credential lands in warnings only when generated."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Domain   string `json:"domain" jsonschema:"the FQDN that receives mail, such as mail.example.com"`
			Adopt    bool   `json:"adopt,omitempty" jsonschema:"reuse an existing Postmark server named mail-DOMAIN / Postmark domain DOMAIN and reconfigure it"`
			LMTPAddr string `json:"lmtp_addr,omitempty" jsonschema:"optional per-domain host:port override of the global LMTP target"`
			HookUser string `json:"hook_user,omitempty" jsonschema:"optional webhook basic-auth user; with hook_pass, both replace the generated credential (then nothing is shown at the end)"`
			HookPass string `json:"hook_pass,omitempty" jsonschema:"optional webhook basic-auth password, at least 24 characters"`
		}) (*mcp.CallToolResult, provisioned, error) {
			v := url.Values{"mail_domain": {in.Domain}}
			if in.LMTPAddr != "" {
				v.Set("mail_lmtp", in.LMTPAddr)
			}
			if in.Adopt {
				v.Set("mail_adopt", "on")
			}
			if in.HookUser != "" {
				v.Set("hook_user", in.HookUser)
				v.Set("hook_pass", in.HookPass)
			}
			warn, err := s.mcpRun(ctx, ip, s.mailProvision, "POST", "/mail/provision", 0, v)
			out, err2 := doneProvisioned(ctx, s, in.Domain, warn, err)
			return nil, out, err2
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "update_mail_domain", Description: "Re-provision (adopt) a mail domain: re-push the webhook configuration, rewrite our own DNS rows to the values Postmark shows now, set the inbound domain and re-check verification. lmtp_addr only sets the per-domain override; blank keeps."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Domain   string `json:"domain"`
			LMTPAddr string `json:"lmtp_addr,omitempty"`
		}) (*mcp.CallToolResult, provisioned, error) {
			v := url.Values{"mail_domain": {in.Domain}, "mail_adopt": {"on"}}
			if in.LMTPAddr != "" {
				v.Set("mail_lmtp", in.LMTPAddr)
			}
			warn, err := s.mcpRun(ctx, ip, s.mailProvision, "POST", "/mail/provision", 0, v)
			out, err2 := doneProvisioned(ctx, s, in.Domain, warn, err)
			return nil, out, err2
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "delete_mail_domain", Description: "Forget one mail domain locally: counters and stored events go. The Postmark server, the Postmark domain and the DNS records are kept."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Domain string `json:"domain"`
		}) (*mcp.CallToolResult, struct {
			Domain string `json:"domain"`
		}, error) {
			_, err := s.mcpRunPath(ctx, ip, s.mailDomainRemove, "POST", "/mail/domains/{name}/delete",
				[][2]string{{"name", strings.ToLower(in.Domain)}}, nil)
			return nil, struct {
				Domain string `json:"domain"`
			}{strings.ToLower(in.Domain)}, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "list_mail_events", Description: "Stored Postmark event notifications, newest first: deliveries, bounces (with the DSN state), spam complaints. Payload is the bounded original JSON.", Annotations: ro},
		func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
			Domain string `json:"domain,omitempty"`
			Limit  int    `json:"limit,omitempty"`
		}) (*mcp.CallToolResult, struct {
			Events []store.MailEvent `json:"events"`
		}, error) {
			var out struct {
				Events []store.MailEvent `json:"events"`
			}
			var id int64
			var err error
			if in.Domain != "" {
				md, gerr := s.deps.Store.GetMailDomain(ctx, in.Domain)
				if gerr != nil {
					return nil, out, fmt.Errorf("mail domain %q is not provisioned", strings.ToLower(in.Domain))
				}
				id = md.ID
			}
			if in.Limit <= 0 || in.Limit > 100 {
				in.Limit = 25
			}
			out.Events, err = s.deps.Store.ListMailEvents(ctx, id, in.Limit)
			return nil, out, err
		})
}

// doneProvisioned reads the freshly written row back; mcpRun's flashes came back as the warnings.
func doneProvisioned(ctx context.Context, s *Server, domain string, warn []string, err error) (provisioned, error) {
	if err != nil {
		return provisioned{}, err
	}
	md, err := s.deps.Store.GetMailDomain(ctx, domain)
	if err != nil {
		return provisioned{}, err
	}
	return provisioned{Domain: mailViewOf(md), Warnings: warn}, nil
}
