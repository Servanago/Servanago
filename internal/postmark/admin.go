// Admin operations on a Postmark account: servers, domains and their webhooks, all with the
// account token. The endpoint shapes follow the gopmstall spikes (verified live): PUT /servers/{id}
// accepts partial updates, DKIM is generated lazily by POST /domains (the pending pair is what a
// new domain publishes), and errors come as {ErrorCode, Message} with a 422.
package postmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var adminEndpoint = "https://api.postmarkapp.com"

const adminTimeout = 30 * time.Second

// Admin is the account-token client.
type Admin struct {
	Token string
}

type pmServer struct {
	ID                         int64  `json:"ID"`
	Name                       string `json:"Name"`
	InboundAddress             string `json:"InboundAddress"`
	InboundHookUrl             string `json:"InboundHookUrl"`
	InboundDomain              string `json:"InboundDomain"`
	RawEmailEnabled            bool   `json:"RawEmailEnabled"`
	BounceHookUrl              string `json:"BounceHookUrl"`
	DeliveryHookUrl            string `json:"DeliveryHookUrl"`
	IncludeBounceContentInHook bool   `json:"IncludeBounceContentInHook"`
	EnableSmtpApiErrorHooks    bool   `json:"EnableSmtpApiErrorHooks"`
}

// Server is the subset of a Postmark server the bridge reads.
type Server struct {
	ID                int64
	Name              string
	InboundAddress    string
	InboundHookURL    string
	InboundDomain     string
	RawEmail          bool
	BounceHookURL     string
	DeliveryHookURL   string
	BounceContent     bool
	SMTPAPIErrorHooks bool
}

// ServerPatch sets the fields the pointer carries and leaves the rest alone.
type ServerPatch struct {
	InboundHookURL    *string
	RawEmail          *bool
	BounceHookURL     *string
	DeliveryHookURL   *string
	BounceContent     *bool
	SMTPAPIErrorHooks *bool
	InboundDomain     *string
}

func (p ServerPatch) json() map[string]any {
	m := map[string]any{}
	if p.InboundHookURL != nil {
		m["InboundHookUrl"] = *p.InboundHookURL
	}
	if p.RawEmail != nil {
		m["RawEmailEnabled"] = *p.RawEmail
	}
	if p.BounceHookURL != nil {
		m["BounceHookUrl"] = *p.BounceHookURL
	}
	if p.DeliveryHookURL != nil {
		m["DeliveryHookUrl"] = *p.DeliveryHookURL
	}
	if p.BounceContent != nil {
		m["IncludeBounceContentInHook"] = *p.BounceContent
	}
	if p.SMTPAPIErrorHooks != nil {
		m["EnableSmtpApiErrorHooks"] = *p.SMTPAPIErrorHooks
	}
	if p.InboundDomain != nil {
		m["InboundDomain"] = *p.InboundDomain
	}
	return m
}

// Domain is the subset of a Postmark domain the bridge needs; the lazy DKIM generation means a
// fresh domain hands out the Pending pair (host is the TXT record name).
type Domain struct {
	ID                       int64  `json:"ID"`
	Name                     string `json:"Name"`
	Status                   string `json:"Status"`
	DKIMHost                 string `json:"DKIMHost"`
	DKIMTextValue            string `json:"DKIMTextValue"`
	DKIMPendingHost          string `json:"DKIMPendingHost"`
	DKIMPendingTextValue     string `json:"DKIMPendingTextValue"`
	ReturnPathDomain         string `json:"ReturnPathDomain"`
	ReturnPathDomainVerified bool   `json:"ReturnPathDomainVerified"`
}

// dkimPair is the TXT record name/value to publish, pending first (verified keys come later).
func (d Domain) DKIMPair() (host, value string) {
	if d.DKIMPendingHost != "" {
		return d.DKIMPendingHost, d.DKIMPendingTextValue
	}
	return d.DKIMHost, d.DKIMTextValue
}

func (a Admin) do(ctx context.Context, method, path string, payload, out any) error {
	var body []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = b
	}
	req, err := http.NewRequestWithContext(ctx, method, adminEndpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Account-Token", a.Token)
	client := &http.Client{Timeout: adminTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("postmark unreachable")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var wrap struct {
		ErrorCode int
		Message   string
	}
	_ = json.Unmarshal(raw, &wrap)
	if resp.StatusCode/100 != 2 || wrap.ErrorCode != 0 {
		return fmt.Errorf("postmark %d code %d: %s", resp.StatusCode, wrap.ErrorCode, wrap.Message)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode postmark reply: %w", err)
		}
	}
	return nil
}

// Servers lists every server, paging through the count/offset API.
func (a Admin) Servers(ctx context.Context) ([]Server, error) {
	var out []Server
	for page := 0; page < 50; page++ {
		var env struct {
			TotalCount int        `json:"TotalCount"`
			Servers    []pmServer `json:"Servers"`
		}
		if err := a.do(ctx, http.MethodGet, fmt.Sprintf("/servers?count=100&offset=%d", page*100), nil, &env); err != nil {
			return nil, err
		}
		for _, s := range env.Servers {
			out = append(out, Server{
				ID: s.ID, Name: s.Name, InboundAddress: s.InboundAddress,
				InboundHookURL: s.InboundHookUrl, InboundDomain: s.InboundDomain, RawEmail: s.RawEmailEnabled,
				BounceHookURL: s.BounceHookUrl, DeliveryHookURL: s.DeliveryHookUrl,
				BounceContent: s.IncludeBounceContentInHook, SMTPAPIErrorHooks: s.EnableSmtpApiErrorHooks,
			})
		}
		if len(env.Servers) < 100 || len(out) >= env.TotalCount {
			return out, nil
		}
	}
	return out, nil
}

// FindServer looks up a server by exact name.
func (a Admin) FindServer(ctx context.Context, name string) (*Server, error) {
	servers, err := a.Servers(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range servers {
		if s.Name == name {
			return &s, nil
		}
	}
	return nil, nil
}

// CreateServer creates a server named name and returns what Postmark says back.
func (a Admin) CreateServer(ctx context.Context, name string) (Server, error) {
	var s pmServer
	err := a.do(ctx, http.MethodPost, "/servers", map[string]string{"Name": name}, &s)
	if err != nil {
		return Server{}, err
	}
	return Server{ID: s.ID, Name: s.Name, InboundAddress: s.InboundAddress}, nil
}

// UpdateServer pushes the patch (nil-pointer fields stay as they are).
func (a Admin) UpdateServer(ctx context.Context, id int64, p ServerPatch) error {
	out := pmServer{}
	return a.do(ctx, http.MethodPut, fmt.Sprintf("/servers/%d", id), p.json(), &out)
}

// ListDomains lists every domain, paging like Servers.
func (a Admin) ListDomains(ctx context.Context) ([]Domain, error) {
	var out []Domain
	for page := 0; page < 50; page++ {
		var env struct {
			TotalCount int      `json:"TotalCount"`
			Domains    []Domain `json:"Domains"`
		}
		if err := a.do(ctx, http.MethodGet, fmt.Sprintf("/domains?count=100&offset=%d", page*100), nil, &env); err != nil {
			return nil, err
		}
		out = append(out, env.Domains...)
		if len(env.Domains) < 100 || len(out) >= env.TotalCount {
			return out, nil
		}
	}
	return out, nil
}

// FindDomain looks up a domain by exact name.
func (a Admin) FindDomain(ctx context.Context, name string) (*Domain, error) {
	domains, err := a.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range domains {
		if d.Name == name {
			return &d, nil
		}
	}
	return nil, nil
}

// CreateDomain creates the Postmark domain with its Return-Path CNAME and returns it.
func (a Admin) CreateDomain(ctx context.Context, name, returnPath string) (Domain, error) {
	var d Domain
	err := a.do(ctx, http.MethodPost, "/domains", map[string]string{"Name": name, "ReturnPathDomain": returnPath}, &d)
	return d, err
}

// Domain fetches one domain by id (to pick up freshly generated DKIM or re-read states).
func (a Admin) GetDomain(ctx context.Context, id int64) (Domain, error) {
	var d Domain
	err := a.do(ctx, http.MethodGet, fmt.Sprintf("/domains/%d", id), nil, &d)
	return d, err
}

// VerifyDkim asks Postmark to check the DKIM TXT now.
func (a Admin) VerifyDkim(ctx context.Context, id int64) (bool, error) {
	var out struct {
		Valid bool `json:"Valid"`
	}
	err := a.do(ctx, http.MethodPut, fmt.Sprintf("/domains/%d/verifyDkim", id), nil, &out)
	return out.Valid, err
}

// VerifyReturnPath asks Postmark to check the Return-Path CNAME now.
func (a Admin) VerifyReturnPath(ctx context.Context, id int64) (bool, error) {
	var out struct {
		Valid bool `json:"Valid"`
	}
	err := a.do(ctx, http.MethodPut, fmt.Sprintf("/domains/%d/verifyReturnPath", id), nil, &out)
	return out.Valid, err
}
