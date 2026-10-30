// The Postmark mail-bridge page: provisioning per domain, verification states, the LMTP
// overrides, and the Settings fieldset. The webhook handlers themselves live in mailhook.go.
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/postmark"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// mailRow is one row of the Mail page.
type mailRow struct {
	store.MailDomain
	HookPath   string // webhook path without credentials
	EventsPath string
}

type mailData struct {
	Ready       bool // Cloudflare configured and SERVANAGO_HOST set
	TokenSet    bool
	LMTPSet     bool
	TLSSet      bool
	Rows        []mailRow
	Events      []store.MailEvent
	DomainNames map[int64]string // event rows: id → domain name
}

func (s *Server) mailOn() bool { return s.dnsOn() && s.deps.Cfg.Host != "" }

func (s *Server) mailPage(w http.ResponseWriter, r *http.Request) {
	d := mailData{Ready: s.mailOn()}
	if d.Ready {
		ctx := r.Context()
		if st, err := s.deps.Store.GetSettings(ctx); err == nil {
			d.TokenSet = st.MailToken != nil
			d.LMTPSet = st.MailLMTP != ""
			d.TLSSet = st.MailTLS == "starttls"
		}
		r0, _ := s.deps.Store.ListMailDomains(ctx)
		d.DomainNames = map[int64]string{}
		for _, md := range r0 {
			d.DomainNames[md.ID] = md.Name
			d.Rows = append(d.Rows, mailRow{MailDomain: md,
				HookPath: "/_mailbridge/hook/" + md.Name, EventsPath: "/_mailbridge/events/" + md.Name})
		}
		d.Events, _ = s.deps.Store.ListMailEvents(ctx, 0, 25)
	}
	s.render(w, "mail", http.StatusOK, page{Title: "Mail", Nav: "mail", Data: d})
}

// postmarkAdmin unseals the account token and builds the client; nothing in scope needs it twice.
func (s *Server) postmarkAdmin(ctx context.Context) (*postmark.Admin, error) {
	st, err := s.deps.Store.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	if st.MailToken == nil {
		return nil, errors.New("set the Postmark account token under Settings first")
	}
	plain, err := secretbox.Open(s.deps.Cfg.SecretKey, st.MailToken)
	if err != nil {
		return nil, err
	}
	return &postmark.Admin{Token: string(plain), URL: s.pmBase}, nil // s.pmBase is a test hook; empty is the real API
}

// mailProvision handles POST /mail/provision: Postmark server + domain (adopt rules), webhook
// credential, hooks push — then DNS, InboundDomain and the verification watch run detached.
func (s *Server) mailProvision(w http.ResponseWriter, r *http.Request) {
	if !s.mailOn() {
		failErr(w, userError{http.StatusForbidden, "The mail bridge needs the Cloudflare DNS feature and SERVANAGO_HOST set."})
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("mail_domain")))
	lmtpOverride := strings.TrimSpace(r.PostFormValue("mail_lmtp"))
	if err := config.ValidateDomain(name); err != nil {
		failErr(w, userError{http.StatusUnprocessableEntity, err.Error()})
		return
	}
	if lmtpOverride != "" {
		if err := validDial(lmtpOverride); err != nil {
			failErr(w, userError{http.StatusUnprocessableEntity, "LMTP target: " + err.Error()})
			return
		}
	}
	ctx, cancel := mailDetached(r)
	defer cancel()
	admin, err := s.postmarkAdmin(ctx)
	if err != nil {
		failErr(w, userError{http.StatusUnprocessableEntity, err.Error()})
		return
	}

	serverName := "mail-" + name
	existingSrv, err := admin.FindServer(ctx, serverName)
	if err != nil {
		failErr(w, userError{http.StatusBadGateway, "Postmark: " + err.Error()})
		return
	}
	returnPath := "pm-bounces." + name
	existingDom, err := admin.FindDomain(ctx, name)
	if err != nil {
		failErr(w, userError{http.StatusBadGateway, "Postmark: " + err.Error()})
		return
	}
	if (existingSrv != nil || existingDom != nil) && r.PostFormValue("mail_adopt") != "on" {
		var what []string
		if existingSrv != nil {
			what = append(what, fmt.Sprintf("Postmark server %q (id %d)", serverName, existingSrv.ID))
		}
		if existingDom != nil {
			what = append(what, fmt.Sprintf("Postmark domain %q (id %d)", name, existingDom.ID))
		}
		failErr(w, userError{http.StatusConflict,
			"Already in Postmark: " + strings.Join(what, " and ") + ". Tick adopt to reuse and update it."})
		return
	}
	var srv postmark.Server
	if existingSrv == nil {
		if srv, err = admin.CreateServer(ctx, serverName); err != nil {
			failErr(w, userError{http.StatusBadGateway, "Postmark: " + err.Error()})
			return
		}
	} else {
		srv = *existingSrv
	}
	var pmDomain postmark.Domain
	if existingDom == nil {
		if pmDomain, err = admin.CreateDomain(ctx, name, returnPath); err != nil {
			failErr(w, userError{http.StatusBadGateway, "Postmark: " + err.Error()})
			return
		}
	} else {
		pmDomain = *existingDom
	}

	// The webhook credential: kept when the row already had one, generated for a new row.
	user, pass, hash := "", "", ""
	genPass := ""
	if cur, gerr := s.deps.Store.GetMailDomain(ctx, name); gerr == nil && cur.HookUser != "" {
		user, hash = cur.HookUser, cur.HookPassHash
	} else {
		user = "mail" + randHex(5)
		genPass = randHex(24)
		pass = genPass
		if hash, err = bcryptHash(pass); err != nil {
			failErr(w, userError{http.StatusInternalServerError, err.Error()})
			return
		}
	}
	// MCP callers may bring their own pair; the UI form never sends these fields. An owned pair
	// is never echoed: genPass empties so the shown-once flash does not fire.
	if u := strings.TrimSpace(r.PostFormValue("hook_user")); u != "" {
		p := strings.TrimSpace(r.PostFormValue("hook_pass"))
		if len(p) < 24 {
			failErr(w, userError{http.StatusUnprocessableEntity, "hook_pass, when set, is at least 24 characters (it is the webhook password)."})
			return
		}
		if !validHookUser(u) {
			failErr(w, userError{http.StatusUnprocessableEntity, "hook_user must be lowercase letters, digits and dashes, 4-24 characters."})
			return
		}
		if hash, err = bcryptHash(p); err != nil {
			failErr(w, userError{http.StatusInternalServerError, err.Error()})
			return
		}
		user, pass, genPass = u, p, ""
	}
	id, _, err := s.deps.Store.UpsertMailDomain(ctx, store.MailDomain{
		Name: name, PMServerID: srv.ID, PMDomainID: pmDomain.ID,
		HookUser: user, HookPassHash: hash, LMTPAddr: lmtpOverride,
	})
	if err != nil {
		failErr(w, userError{http.StatusInternalServerError, err.Error()})
		return
	}

	hookURL := s.webhookBase() + "/_mailbridge/hook/" + name
	eventsURL := s.webhookBase() + "/_mailbridge/events/" + name
	fullHook := embedCred(hookURL, user, pass)
	fullEvents := embedCred(eventsURL, user, pass)
	err = admin.UpdateServer(ctx, srv.ID, postmark.ServerPatch{
		InboundHookURL:    &fullHook,
		RawEmail:          bptr(true),
		BounceHookURL:     &fullEvents,
		DeliveryHookURL:   &fullEvents,
		BounceContent:     bptr(true),
		SMTPAPIErrorHooks: bptr(true),
	})
	if err != nil {
		slog.Error("mail bridge hooks push", "domain", name, "error", err)
		s.audit(r, "mail.hooks", "push failed: "+err.Error())
		s.flash("Provisioned Postmark for " + name + ", but pushing the webhook settings failed: " + err.Error() +
			". Provision again (tick adopt) once the account token works.")
		hxRedirect(w, "/mail")
		return
	}
	s.audit(r, "mail.provisioned", name+" server="+strconv.FormatInt(srv.ID, 10))

	lines := []string{"Mail bridge for " + name + " is provisioned."}
	if genPass != "" { // a kept or owned credential is never re-shown
		lines = append(lines, "Hook user: "+user+" — password (shown once): "+genPass)
		lines = append(lines, "Webhook URL (shown once): "+fullHook)
		lines = append(lines, "Events URL (shown once): "+fullEvents)
	} else {
		lines = append(lines, "The existing webhook credential is unchanged.")
	}
	if lmtpOverride != "" {
		lines = append(lines, "LMTP for this domain points at "+lmtpOverride+".")
	}
	lines = append(lines, "DNS records, the inbound domain and Postmark verification are applied in the background.")
	for _, l := range lines {
		s.flash(l)
	}
	gctx, gcancel := mailDetached(r)
	job := mailApplyJob{admin, id, name, pmDomain.ID}
	if s.applyInline { // test seam: production detaches; tests watch the pass finish
		s.mailApply(gctx, job)
		gcancel()
	} else {
		go func() {
			defer gcancel()
			s.mailApply(gctx, job)
		}()
	}
	hxRedirect(w, "/mail")
}

// mailApplyJob carries what the detached DNS + verify pass needs.
type mailApplyJob struct {
	admin    *postmark.Admin
	rowID    int64
	name     string
	domainID int64
}

// mailApply writes the DNS rows, then the inbound domain, then watches verification.
func (s *Server) mailApply(ctx context.Context, j mailApplyJob) {
	// Re-read: the row has what the webhook needs, Postmark has the pending DKIM.
	d, err := j.admin.GetDomain(ctx, j.domainID)
	if err != nil {
		s.failApply(ctx, j, "Postmark domain read: "+err.Error())
		return
	}
	dkimHost, dkimText := d.DKIMPair()
	returnPath := d.ReturnPathDomain
	if returnPath == "" {
		returnPath = "pm-bounces." + j.name
	}
	notes := s.mailWriteDNS(ctx, j.name, dkimHost, dkimText, returnPath)
	if err := s.deps.Store.SetMailDNS(ctx, j.rowID, dkimHost, dkimText, returnPath, strings.Join(notes, "\n")); err != nil {
		slog.Error("mail bridge dns state", "error", err)
	}
	if err := j.admin.UpdateServer(ctx, s.mailServerIDFor(ctx, j), postmark.ServerPatch{InboundDomain: &j.name}); err != nil {
		slog.Warn("mail bridge inbound domain", "domain", j.name, "error", err)
		notes = append(notes, "InboundDomain not set: "+err.Error())
		_ = s.deps.Store.SetMailDNS(ctx, j.rowID, dkimHost, dkimText, returnPath, strings.Join(notes, "\n"))
	}
	s.mailVerifyWatch(ctx, j.domainID, j.rowID)
}

// mailServerIDFor is the server id of the row (UpdateServer needs it detached).
func (s *Server) mailServerIDFor(ctx context.Context, j mailApplyJob) int64 {
	if d, err := s.deps.Store.GetMailDomain(ctx, j.name); err == nil {
		return d.PMServerID
	}
	return 0
}

func (s *Server) failApply(ctx context.Context, j mailApplyJob, msg string) {
	slog.Error("mail bridge apply", "domain", j.name, "error", msg)
	if cur, err := s.deps.Store.GetMailDomain(ctx, j.name); err == nil {
		_ = s.deps.Store.SetMailDNS(ctx, cur.ID, cur.DKIMHost, cur.DKIMText, cur.ReturnPath, cur.DNSSetup+"\n"+msg)
	}
}

// mailWriteDNS ensures the four Postmark rows through the admin DNS CRUD: never deletes, never
// rewrites a foreign SPF, records one note per row.
func (s *Server) mailWriteDNS(ctx context.Context, name, dkimHost, dkimText, returnPath string) (notes []string) {
	note := func(s string) { notes = append(notes, s) }
	zoneID, _, err := s.deps.CF.ZoneFor(ctx, name, "")
	if err != nil {
		return []string{
			"no Cloudflare zone for " + name + ": publish by hand:",
			"MX " + name + " 10 inbound.postmarkapp.com",
			"TXT " + name + ` "v=spf1 include:spf.mtasv.net ~all"`,
			"TXT " + dkimHost + " " + dkimText,
			"CNAME " + returnPath + " pm.mtasv.net",
		}
	}
	records, err := s.deps.CF.ListRecords(ctx, zoneID)
	if err != nil {
		return []string{"list records: " + err.Error()}
	}
	find := func(t, n string) *cfdns.FullRecord {
		for _, rec := range records {
			if rec.Type == t && strings.EqualFold(rec.Name, n) {
				return &rec
			}
		}
		return nil
	}
	ensure := func(t, n, content string, priority int) {
		if cur := find(t, n); cur != nil {
			cur.Content = strings.TrimSpace(cur.Content)
			if strings.EqualFold(cur.Content, content) && (t != "MX" || cur.Priority == priority) {
				note(t + " " + n + " ok (id " + cur.ID + ")")
				return
			}
			if cur.Comment != cfdns.ManagedComment {
				note(t + " " + n + " exists with " + strconv.Quote(cur.Content) + " and was left untouched")
				return
			}
			cur.Content, cur.Comment, cur.Priority = content, cfdns.ManagedComment, priority
			if err := s.deps.CF.UpdateRecordFull(ctx, zoneID, cur.ID, *cur); err != nil {
				note(t + " " + n + " update failed: " + err.Error())
				return
			}
			note(t + " " + n + " fixed (id " + cur.ID + ")")
			return
		}
		fr := cfdns.FullRecord{Type: t, Name: n, Content: content, TTL: 3600, Priority: priority, Comment: cfdns.ManagedComment}
		id, err := s.deps.CF.CreateRecordFull(ctx, zoneID, fr)
		if err != nil {
			note(t + " " + n + " create failed: " + err.Error())
			return
		}
		note(t + " " + n + " written (id " + id + ")")
	}
	ensure("MX", name, "inbound.postmarkapp.com", 10)
	ensure("CNAME", returnPath, "pm.mtasv.net", 0)
	ensure("TXT", dkimHost, dkimText, 0)
	// SPF: only created when absent; a foreign row without the include is a hand job.
	spf := "v=spf1 include:spf.mtasv.net ~all"
	cur := find("TXT", name)
	switch {
	case cur == nil:
		ensure("TXT", name, spf, 0)
	case strings.Contains(cur.Content, "spf.mtasv.net"):
		note("SPF already carries the Postmark include")
	case cur.Comment == cfdns.ManagedComment:
		cur.Content, cur.Priority = spf, 0
		if err := s.deps.CF.UpdateRecordFull(ctx, zoneID, cur.ID, *cur); err != nil {
			note("SPF update failed: " + err.Error())
		} else {
			note("SPF rewritten to " + cur.Content)
		}
	default:
		note("an existing SPF at " + name + " has no Postmark include; add \"include:spf.mtasv.net\" by hand")
	}
	return notes
}

// mailVerifyWatch polls Postmark's verify calls once in a while for the loop window, storing states.
func (s *Server) mailVerifyWatch(ctx context.Context, pmDomainID, rowID int64) {
	dk, rp := "pending", "pending"
	_ = s.deps.Store.SetMailVerifyStates(ctx, rowID, dk, rp)
	poll, tries := s.mailPoll, s.mailTries
	if poll == 0 {
		poll = time.Minute
	}
	for i := 0; i < tries; i++ {
		okD, errD := s.verifyOne(ctx, pmDomainID, true)
		okR, errR := s.verifyOne(ctx, pmDomainID, false)
		switch {
		case errD != nil:
			slog.Warn("mail bridge verify", "domain-id", pmDomainID, "what", "dkim", "error", errD)
		case errR != nil:
			slog.Warn("mail bridge verify", "domain-id", pmDomainID, "what", "return-path", "error", errR)
		}
		if errD == nil {
			dk = mailState(okD)
		}
		if errR == nil {
			rp = mailState(okR)
		}
		_ = s.deps.Store.SetMailVerifyStates(ctx, rowID, dk, rp)
		if dk == "verified" && rp == "verified" {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
}

// mailState turns one verify answer into the stored state.
func mailState(ok bool) string {
	if ok {
		return "verified"
	}
	return "failed"
}

// verifyOne is verifyDkim or verifyReturnPath; the mailDomainVerify route calls it once.
func (s *Server) verifyOne(ctx context.Context, pmDomainID int64, dkim bool) (bool, error) {
	admin, err := s.postmarkAdmin(ctx)
	if err != nil {
		return false, err
	}
	if dkim {
		return admin.VerifyDkim(ctx, pmDomainID)
	}
	return admin.VerifyReturnPath(ctx, pmDomainID)
}

// mailDomainVerify handles POST /mail/domains/{name}/verify: one immediate check.
func (s *Server) mailDomainVerify(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	ctx, cancel := mailDetached(r)
	defer cancel()
	md, err := s.deps.Store.GetMailDomain(ctx, name)
	if err != nil {
		failErr(w, userError{http.StatusNotFound, "no such mail domain"})
		return
	}
	if md.PMDomainID == 0 {
		failErr(w, userError{http.StatusUnprocessableEntity, name + " has no Postmark domain yet"})
		return
	}
	dk, errD := s.verifyOne(ctx, md.PMDomainID, true)
	rp, errR := s.verifyOne(ctx, md.PMDomainID, false)
	if errD != nil || errR != nil {
		slog.Warn("mail bridge verify", "domain", name, "dkim-error", errD, "rp-error", errR)
		failErr(w, userError{http.StatusBadGateway, "Postmark: " + firstNonEmpty(errText(errD), errText(errR))})
		return
	}
	if err := s.deps.Store.SetMailVerifyStates(ctx, md.ID, mailState(dk), mailState(rp)); err != nil {
		failErr(w, userError{http.StatusInternalServerError, err.Error()})
		return
	}
	s.audit(r, "mail.verified", fmt.Sprintf("%s dkim=%s rp=%s", name, strconv.FormatBool(dk), strconv.FormatBool(rp)))
	hxRedirect(w, "/mail")
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// saveDomainLMTP handles POST /mail/domains/{name}/lmtp: the per-domain endpoint override.
func (s *Server) saveDomainLMTP(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	addr := strings.TrimSpace(r.PostFormValue("lmtp_addr"))
	if addr != "" {
		if err := validDial(addr); err != nil {
			failErr(w, userError{http.StatusUnprocessableEntity, err.Error()})
			return
		}
	}
	ctx := r.Context()
	md, err := s.deps.Store.GetMailDomain(ctx, name)
	if err != nil {
		failErr(w, userError{http.StatusNotFound, "no such mail domain"})
		return
	}
	md.LMTPAddr = addr
	if _, _, err := s.deps.Store.UpsertMailDomain(ctx, md); err != nil {
		failErr(w, userError{http.StatusInternalServerError, err.Error()})
		return
	}
	s.audit(r, "mail.lmtp", name+"="+addr)
	hxRedirect(w, "/mail")
}

// mailDomainRemove forgets the domain locally; Postmark and the DNS rows stay.
func (s *Server) mailDomainRemove(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	if err := s.deps.Store.DeleteMailDomain(r.Context(), name); err != nil {
		failErr(w, userError{http.StatusUnprocessableEntity, err.Error()})
		return
	}
	s.audit(r, "mail.removed", name)
	hxRedirect(w, "/mail")
}

// saveMail handles POST /settings/mail: the account token and the global LMTP target.
func (s *Server) saveMail(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cur, err := s.deps.Store.GetSettings(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	st := cur // every column not on this form carries over
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	st.MailLMTP = strings.TrimSpace(r.PostFormValue("mail_lmtp"))
	if st.MailLMTP != "" {
		if err := validDial(st.MailLMTP); err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	st.MailTLS = ""
	if r.PostFormValue("mail_tls") == "on" {
		st.MailTLS = "starttls"
	}
	st.MailUser = strings.TrimSpace(r.PostFormValue("mail_user"))
	switch pw := strings.TrimSpace(r.PostFormValue("mail_pass")); {
	case pw != "" && s.deps.Cfg.SecretKey == "":
		fail(w, http.StatusUnprocessableEntity, "Storing an LMTP password needs SERVANAGO_SECRET_KEY in the environment. Leave it blank for a loopback server that asks for none.")
		return
	case pw != "":
		if st.MailPass, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(pw)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	switch tok := strings.TrimSpace(r.PostFormValue("mail_token")); {
	case tok != "" && s.deps.Cfg.SecretKey == "":
		fail(w, http.StatusUnprocessableEntity, "Storing the Postmark account token needs SERVANAGO_SECRET_KEY in the environment file.")
		return
	case tok != "":
		if st.MailToken, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(tok)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.deps.Store.SaveSettings(r.Context(), st); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "settings.mail", "lmtp="+st.MailLMTP)
	hxRedirect(w, "/settings")
}

// webhookBase is the panel's public origin.
func (s *Server) webhookBase() string { return "https://" + s.deps.Cfg.Host }

// embedCred puts the basic-auth pair into the URL the way Postmark expects it (verified: the
// header arrives with the exact pair).
func embedCred(url, user, pass string) string {
	if pass == "" {
		return url
	}
	i := strings.Index(url, "://")
	if i < 0 {
		return url
	}
	return url[:i+3] + user + ":" + pass + "@" + url[i+3:]
}

func bptr(b bool) *bool { return &b }

// validDial accepts host:port only (the LMTP and webhook targets).
func validDial(s string) error {
	h, p, err := net.SplitHostPort(s)
	if err != nil || p == "" {
		return errors.New("needs the form host:port, such as 192.168.1.9:2424")
	}
	n, perr := strconv.Atoi(p)
	if perr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q is not 1-65535", p)
	}
	if h == "" {
		return errors.New("host is empty")
	}
	return nil
}

// randHex is a fresh token for webhook credentials.
func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "unavailable" // crypto/rand only fails on a broken system
	}
	return hex.EncodeToString(b)[:n]
}

// validHookUser is the webhook basic-auth user's shape: lowercase letters, digits, dashes.
func validHookUser(u string) bool {
	if len(u) < 4 || len(u) > 24 {
		return false
	}
	for _, r := range u {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func bcryptHash(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// mailDetached outlives the request: provisioning and the verify window must not die with the tab.
func mailDetached(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 20*time.Minute)
}
