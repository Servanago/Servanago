// The Postmark webhooks mount on the top mux beside /mcp: no cookie, no CSRF — basic auth
// against the domain's own credential (bcrypt is constant-time). Postmark retries non-200s
// 10 times over ~9 h and stops on 403; the classes are in mailbridge.Result.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/mailbridge"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// mailHook handles POST /hook/<domain>: the raw message → LMTP, deduped, counted.
func (s *Server) mailHook(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	md, err := s.deps.Store.GetMailDomain(r.Context(), name)
	if err != nil {
		mailBridgeErr(w, http.StatusNotFound, "unknown mail domain")
		return
	}
	if !s.mailAuth(w, r, md) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, mailbridge.MaxBody)
	var in mailbridge.Inbound
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			mailBridgeErr(w, http.StatusRequestEntityTooLarge, "payload too large")
			return
		}
		mailBridgeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if in.MessageID == "" {
		mailBridgeErr(w, http.StatusBadRequest, "missing MessageID")
		return
	}
	s.postInbound(r.Context(), md, &in, w)
}

// postInbound is the domain-checked half of the inbound flow (testable without the route).
func (s *Server) postInbound(ctx context.Context, md store.MailDomain, in *mailbridge.Inbound, w http.ResponseWriter) {
	rcpt := in.Recipient()
	if rcpt == "" {
		mailBridgeErr(w, http.StatusBadRequest, "no envelope recipient in the payload")
		return
	}
	if rcptDomain(rcpt) != md.Name && !strings.EqualFold(rcptDomain(rcpt), md.Name) {
		slog.Warn("mail bridge: recipient outside the webhook domain", "domain", md.Name, "rcpt", rcpt)
		_ = s.countAnd(ctx, md, "rejected", false)
		mailBridgeErr(w, http.StatusForbidden, "recipient not in the configured domain")
		return
	}
	if err := s.countAnd(ctx, md, "recv", true); err != nil {
		mailBridgeErr(w, http.StatusInternalServerError, "storage error")
		return
	}
	key := sha256hex(in.MessageID + "|" + rcpt)
	seen, err := s.deps.Store.Delivered(ctx, key)
	if err != nil {
		mailBridgeErr(w, http.StatusInternalServerError, "storage error")
		return
	}
	if seen {
		_ = s.countAnd(ctx, md, "deduped", false)
		w.WriteHeader(http.StatusOK) // a retry after a lost 200 must not produce a second copy
		return
	}
	msgBytes, plainBranch, ok := mailbridge.DecodeRaw(in.RawEmail)
	if ok {
		slog.Info("mail bridge inbound", "event", "mail.inbound", "domain", md.Name, "raw", rawKind(plainBranch))
	} else { // rebuild from the JSON fields; the original DKIM cannot verify after this
		msgBytes, err = mailbridge.BuildMIME(in)
		if err != nil {
			slog.Error("mail bridge rebuild", "domain", md.Name, "error", err)
			mailBridgeErr(w, http.StatusUnprocessableEntity, "message not reconstructable")
			return
		}
		_ = s.countAnd(ctx, md, "fallbacks", false)
		slog.Info("mail bridge inbound", "event", "mail.inbound", "domain", md.Name, "raw", "rebuild")
	}
	res, derr := s.deliverLMTP(ctx, md, in.Sender(), rcpt, msgBytes)
	switch {
	case derr != nil:
		slog.Error("mail bridge lmtp", "domain", md.Name, "result", res, "error", derr)
	case res == mailbridge.ResultOK:
		// The dedupe key is recorded only on success: a temporary failure's next attempt
		// must still deliver (at-least-once; concurrent first attempts both deliver and the
		// LMTP server's own Message-ID dedupe is the second net). gopmstall's rule.
		if _, err := s.deps.Store.DeliverOnce(ctx, key, md.ID); err != nil {
			slog.Error("mail bridge dedupe record", "domain", md.Name, "error", err)
		}
		_ = s.countAnd(ctx, md, "delivered", false)
	}
	switch res {
	case mailbridge.ResultOK:
		w.WriteHeader(http.StatusOK)
	case mailbridge.ResultTemporary:
		w.WriteHeader(http.StatusServiceUnavailable)
	default: // failed: Postmark stops retrying; a mailbox that will never exist is the usual cause
		_ = s.countAnd(ctx, md, "rejected", false)
		w.WriteHeader(http.StatusForbidden)
	}
}

func rcptDomain(rcpt string) string {
	if i := strings.LastIndex(rcpt, "@"); i >= 0 {
		return rcpt[i+1:]
	}
	return rcpt
}

func rawKind(plain bool) string {
	if plain {
		return "plain"
	}
	return "base64"
}

func eventKey(e mailbridge.Event) string {
	if e.ID != 0 {
		return strconv.FormatInt(e.ID, 10)
	}
	return ""
}

// mailEvents handles POST /events/<domain>: store the event, answer a bounce with a DSN.
func (s *Server) mailEvents(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	md, err := s.deps.Store.GetMailDomain(r.Context(), name)
	if err != nil {
		mailBridgeErr(w, http.StatusNotFound, "unknown mail domain")
		return
	}
	if !s.mailAuth(w, r, md) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, mailbridge.MaxEventBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		mailBridgeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	e, err := mailbridge.UnmarshalEvent(body)
	if err != nil || e.RecordType == "" {
		mailBridgeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	eid, err := s.deps.Store.InsertMailEvent(r.Context(), mailEventRow(md.ID, e, body))
	if err != nil {
		slog.Error("mail bridge event store", "error", err)
		mailBridgeErr(w, http.StatusInternalServerError, "storage error")
		return
	}
	s.sendBounceDSN(r.Context(), md, e, eid)
	w.WriteHeader(http.StatusOK)
}

// mailEventRow extracts the indexed fields and bounds the stored payload.
func mailEventRow(domainID int64, e mailbridge.Event, body []byte) store.MailEvent {
	return store.MailEvent{
		DomainID:   domainID,
		RecordType: e.RecordType,
		RecordID:   eventKey(e),
		MessageID:  e.MessageID,
		Address:    firstNonEmpty(e.From, e.Email),
		Summary:    firstNonEmpty(e.Description, e.Details, e.Type),
		Payload:    boundText(body, mailbridge.MaxPayload),
	}
}

// sendBounceDSN rebuilds and delivers the RFC 3464 report; deduped on the bounce ID so
// Postmark's own retries of this POST cannot send the DSN twice.
func (s *Server) sendBounceDSN(ctx context.Context, md store.MailDomain, e mailbridge.Event, eid int64) {
	if e.RecordType != "Bounce" || e.From == "" { // spam complaints and From-less bounces are log-only
		return
	}
	if mailbridge.MailerDaemonLoop(e.From) {
		slog.Warn("mail bridge: bounce From would loop", "domain", md.Name)
		return
	}
	fresh, err := s.deps.Store.DeliverOnce(ctx, "bounce:"+eventKey(e), md.ID)
	if err != nil {
		slog.Error("mail bridge dsn dedupe", "error", err)
		return
	}
	if !fresh {
		return
	}
	raw, err := mailbridge.BuildDSN(md.Name, e)
	if err != nil {
		slog.Error("mail bridge dsn build", "domain", md.Name, "error", err)
		return
	}
	res, derr := s.deliverLMTP(ctx, md, "MAILER-DAEMON@"+md.Name, e.From, raw)
	switch {
	case res == mailbridge.ResultOK:
		_ = s.deps.Store.MarkMailEventDSN(ctx, eid)
	default:
		slog.Error("mail bridge dsn deliver", "domain", md.Name, "result", res, "error", derr)
	}
}

// deliverLMTP resolves the target and sends; the per-domain override replaces the endpoint
// only (TLS and the global credential apply). ponytail: per-domain auth columns on demand.
func (s *Server) deliverLMTP(ctx context.Context, md store.MailDomain, from, rcpt string, msg []byte) (mailbridge.Result, error) {
	st, err := s.deps.Store.GetSettings(ctx)
	if err != nil {
		return mailbridge.ResultTemporary, err
	}
	addr := st.MailLMTP
	if md.LMTPAddr != "" {
		addr = md.LMTPAddr
	}
	pass := ""
	if st.MailPass != nil {
		if s.deps.Cfg.SecretKey == "" {
			return mailbridge.ResultTemporary, errors.New("SERVANAGO_SECRET_KEY is gone; the sealed LMTP credential cannot be read")
		}
		var plain []byte
		if plain, err = secretbox.Open(s.deps.Cfg.SecretKey, st.MailPass); err != nil {
			return mailbridge.ResultTemporary, err
		}
		pass = string(plain)
	}
	t := mailbridge.Target{HostPort: addr, TLS: st.MailTLS == "starttls", User: st.MailUser, Pass: pass}
	return mailbridge.Deliver(ctx, t, s.deps.Cfg.Host, from, rcpt, msg)
}

// mailAuth checks the per-domain basic-auth pair.
func (s *Server) mailAuth(w http.ResponseWriter, r *http.Request, md store.MailDomain) bool {
	u, p, ok := r.BasicAuth()
	if ok && u == md.HookUser && len(md.HookPassHash) > 0 {
		if bcrypt.CompareHashAndPassword([]byte(md.HookPassHash), []byte(p)) == nil {
			return true
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="mail bridge"`)
	w.WriteHeader(http.StatusUnauthorized)
	return false
}

// countAnd bumps one named counter (closed list in the store).
func (s *Server) countAnd(ctx context.Context, md store.MailDomain, kind string, lastInbound bool) error {
	if err := s.deps.Store.CountMail(ctx, md.ID, lastInbound, kind); err != nil {
		slog.Error("mail bridge counter", "domain", md.Name, "error", err)
		return err
	}
	return nil
}

func mailBridgeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(b)
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			return p
		}
	}
	return ""
}

func boundText(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}
