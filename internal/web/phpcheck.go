package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/runtimes"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/smtpx"
	"github.com/servanago/servanago/internal/store"
)

// phpcheck.go: the PHP release check. It reads php.net's list of supported branches (with their latest release and
// whether it is a security release), stores the result, and tells the admin when a branch they run has a newer release.
// It never builds or switches anything.

const (
	phpFeed       = "https://www.php.net/releases/active.php"
	phpCheckEvery = 7 * 24 * time.Hour
)

type phpRelease struct {
	Version  string `json:"version"`
	Security bool   `json:"security,omitempty"`
	Date     string `json:"date,omitempty"`
}

// phpCheckResult is what the settings row keeps between checks.
type phpCheckResult struct {
	Latest   map[string]phpRelease `json:"latest"`             // supported branch (8.4) -> its latest release
	Notified string                `json:"notified,omitempty"` // the pending-updates signature already mailed
}

type phpUpdate struct {
	Branch, Version string
	Security        bool
}

// parsePHPFeed reads active.php: {"8": {"8.4": {"version": "8.4.27", "tags": ["security"], "date": "..."}}}.
func parsePHPFeed(b []byte) (map[string]phpRelease, error) {
	var raw map[string]map[string]struct {
		Version string   `json:"version"`
		Tags    []string `json:"tags"`
		Date    string   `json:"date"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("php.net feed: %w", err)
	}
	out := map[string]phpRelease{}
	for _, branches := range raw {
		for branch, r := range branches {
			if !phpBranchRE.MatchString(branch) || !phpVersionRE.MatchString(r.Version) || runtimes.Branch(r.Version) != branch {
				return nil, fmt.Errorf("php.net feed: unexpected entry %q = %q", branch, r.Version)
			}
			sec := false
			for _, t := range r.Tags {
				sec = sec || t == "security"
			}
			out[branch] = phpRelease{Version: r.Version, Security: sec, Date: r.Date}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("php.net feed lists no supported branch")
	}
	return out, nil
}

// pendingUpdates lists the supported branches the host has a ServanaGo build of whose newest build is older than php.net's latest.
func pendingUpdates(latest map[string]phpRelease, installed []runtimes.PHPVersion) []phpUpdate {
	have := map[string]string{} // branch -> newest installed version without the build number
	for _, p := range installed {
		if p.Source && runtimes.BuildRE.MatchString(p.Version) {
			v := p.Version[:strings.LastIndex(p.Version, "-")]
			if cur, ok := have[runtimes.Branch(v)]; !ok || runtimes.Newer(v, cur) {
				have[runtimes.Branch(v)] = v
			}
		}
	}
	var out []phpUpdate
	for branch, cur := range have {
		if rel, ok := latest[branch]; ok && runtimes.Newer(rel.Version, cur) {
			out = append(out, phpUpdate{Branch: branch, Version: rel.Version, Security: rel.Security})
		}
	}
	sort.Slice(out, func(i, j int) bool { return runtimes.Newer(out[i].Branch, out[j].Branch) })
	return out
}

func signature(u []phpUpdate) string {
	var parts []string
	for _, x := range u {
		parts = append(parts, x.Version+map[bool]string{true: "!"}[x.Security])
	}
	return strings.Join(parts, ",")
}

func (s *Server) httpGet(ctx context.Context, rawURL string) ([]byte, error) {
	if s.deps.HTTPGet != nil {
		return s.deps.HTTPGet(ctx, rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (s *Server) loadCheck(ctx context.Context) (phpCheckResult, int64) {
	js, at, err := s.deps.Store.PHPCheck(ctx)
	var res phpCheckResult
	if err != nil || js == "" || json.Unmarshal([]byte(js), &res) != nil {
		return phpCheckResult{}, 0
	}
	return res, at
}

// runPHPCheck fetches the feed, stores it, and mails the admin when the set of pending updates changed.
func (s *Server) runPHPCheck(ctx context.Context) error {
	body, err := s.httpGet(ctx, phpFeed)
	if err != nil {
		return fmt.Errorf("php.net release feed: %w", err)
	}
	latest, err := parsePHPFeed(body)
	if err != nil {
		return err
	}
	prev, _ := s.loadCheck(ctx)
	res := phpCheckResult{Latest: latest, Notified: prev.Notified}
	pending := pendingUpdates(latest, s.detect(ctx).PHP)
	if sig := signature(pending); sig == "" {
		res.Notified = ""
	} else if sig != prev.Notified {
		if err := s.mailUpdates(ctx, pending); err != nil {
			slog.Warn("php update mail not sent", "error", err) // the banner still shows it; try again at the next check
		} else {
			res.Notified = sig
		}
	}
	js, _ := json.Marshal(res)
	if err := s.deps.Store.SavePHPCheck(ctx, string(js), time.Now().Unix()); err != nil {
		return err
	}
	s.auditSystem(ctx, "php.check", signature(pending))
	return nil
}

func (s *Server) auditSystem(ctx context.Context, action, target string) {
	e := store.AuditEntry{At: time.Now().UTC().Format(time.RFC3339), Actor: "system", Action: action, Target: tidy(target, 200)}
	if err := s.deps.Store.AddAudit(context.WithoutCancel(ctx), e); err != nil {
		slog.Error("write audit row", "action", action, "error", err)
	}
}

func (s *Server) mailUpdates(ctx context.Context, pending []phpUpdate) error {
	set, err := s.deps.Store.GetSettings(ctx)
	if err != nil {
		return err
	}
	if !set.MailReady() {
		return fmt.Errorf("email delivery is not set up")
	}
	var lines []string
	for _, u := range pending {
		lines = append(lines, fmt.Sprintf("PHP %s is available for the %s branch%s.", u.Version, u.Branch, map[bool]string{true: " (a security release)"}[u.Security]))
	}
	body := strings.Join(lines, "\n") + "\n\nOpen the PHP page in ServanaGo to build it and switch your sites. Nothing was changed.\n"
	// ponytail: no admin email address exists in ServanaGo, so the notice goes to the MAIL FROM mailbox
	return s.sendMail(set.MailFrom, set.MailFrom, "ServanaGo: a new PHP release is available", body)
}

// smtpMail sends through the Settings page's SMTP account; the password is unsealed only here.
func (s *Server) smtpMail(from, to, subject, body string) error {
	set, err := s.deps.Store.GetSettings(context.Background())
	if err != nil {
		return err
	}
	var pw string
	if set.SMTPPass != nil {
		b, err := secretbox.Open(s.deps.Cfg.SecretKey, set.SMTPPass)
		if err != nil {
			return fmt.Errorf("unseal the SMTP password: %w", err)
		}
		pw = string(b)
	}
	return smtpx.Dialer{Host: set.SMTPHost, Port: set.SMTPPort, User: set.SMTPUser, Pass: pw}.Send(from, to, subject, body)
}

// RunPHPChecks checks php.net once a week (and at start when the last check is older than that) until ctx ends.
func (s *Server) RunPHPChecks(ctx context.Context) {
	for {
		if _, at := s.loadCheck(ctx); time.Since(time.Unix(at, 0)) >= phpCheckEvery {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			if err := s.runPHPCheck(cctx); err != nil {
				slog.Warn("php release check failed", "error", err)
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour): // the check itself only runs when a week has passed
		}
	}
}

// localHealthGet requests path from this machine's own Caddy as host and returns the status. The certificate is not
// verified: the connection never leaves loopback, and a certificate that is not issued yet must not fail a PHP switch.
func (s *Server) localHealthGet(ctx context.Context, host, path string) (int, error) {
	port := s.deps.Cfg.HTTPSPort
	if port == 0 {
		port = 443
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(port))
			},
			TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec // loopback only, see above
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := url.URL{Scheme: "https", Host: host}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
