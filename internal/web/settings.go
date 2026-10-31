// The Settings page: app-level email delivery for magic-link site access.
// The SMTP password is sealed with secretbox (SERVANAGO_SECRET_KEY) and never logged.
package web

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/gatelogic"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

type smtpData struct {
	Tab       string // the selected settingsTabs key
	Host      string
	Port      string // text for the input's value
	User      string
	From      string
	PassSet   bool // a sealed password exists
	MailReady bool // host and sender set: the gate can send
	// The virus-scanning section.
	ScanOn   bool   // a clamd socket is set
	Socket   string // the configured path
	Hour     string
	NtfySet  bool
	NtfyURL  string // the stored topic URL, unsealed for display; empty when unreadable
	TokenSet bool
	// The country-filter section.
	GeoOn          bool
	GeoDB          string
	WebUIMode      string
	WebUICountries string
	// The mail-bridge section.
	MailOn       bool // Cloudflare configured: the bridge can provision
	MailTokenSet bool
	MailLMTP     string
	MailTLS      bool
	MailUser     string
	MailPassSet  bool
}

// settingsTabs are the Settings page's tabs in order; the key is the /settings/{tab} path segment.
var settingsTabs = []struct{ Key, Label string }{
	{"email", "Email delivery"}, {"scan", "Virus scanning"}, {"notify", "Notifications"},
	{"geo", "Country filter"}, {"mail", "Mail bridge"},
}

// settingsIndex sends /settings to the first tab.
func settingsIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/settings/"+settingsTabs[0].Key, http.StatusSeeOther)
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	tab := r.PathValue("tab")
	known := false
	for _, t := range settingsTabs {
		known = known || t.Key == tab
	}
	if !known {
		http.NotFound(w, r)
		return
	}
	st, err := s.deps.Store.GetSettings(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := smtpData{
		Tab:  tab,
		Host: st.SMTPHost, Port: strconv.Itoa(st.SMTPPort), User: st.SMTPUser, From: st.MailFrom,
		PassSet: st.SMTPPass != nil, MailReady: st.MailReady(),
		ScanOn: st.ScanSocket != "", Socket: st.ScanSocket, Hour: strconv.Itoa(st.ScanHour),
		NtfySet: st.ScanNtfy != nil, TokenSet: st.ScanNtfyToken != nil,
		GeoOn: st.GeoDB != "", GeoDB: st.GeoDB, WebUIMode: st.WebUIMode, WebUICountries: st.WebUICountries,
		MailOn: st.MailToken != nil, MailTokenSet: st.MailToken != nil, MailLMTP: st.MailLMTP,
		MailTLS: st.MailTLS == "starttls", MailUser: st.MailUser, MailPassSet: st.MailPass != nil}
	if st.ScanNtfy != nil && s.deps.Cfg.SecretKey != "" { // the topic URL is not itself a secret: show it
		if url, err := secretbox.Open(s.deps.Cfg.SecretKey, st.ScanNtfy); err == nil {
			d.NtfyURL = string(url)
		} else {
			slog.Error("unseal the ntfy topic URL", "error", err)
		}
	}
	s.render(w, "settings", http.StatusOK, page{Title: "Settings", Data: d})
}

// saveNotify stores the Notifications tab: the ntfy topic URL and its access token. A blank
// topic keeps the stored pair; clear_ntfy drops both.
func (s *Server) saveNotify(w http.ResponseWriter, r *http.Request) {
	cur, err := s.deps.Store.GetSettings(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	st := cur
	clear := r.PostFormValue("clear_ntfy") != ""
	ntfy := strings.TrimSpace(r.PostFormValue("scan_ntfy"))
	switch {
	case clear:
		st.ScanNtfy, st.ScanNtfyToken = nil, nil
	case ntfy == "":
	case s.deps.Cfg.SecretKey == "":
		fail(w, http.StatusUnprocessableEntity, "Storing the ntfy address needs SERVANAGO_SECRET_KEY (at least 32 characters) in the environment file.")
		return
	default:
		if !strings.HasPrefix(ntfy, "https://") || len(ntfy) > 500 || strings.ContainsAny(ntfy, " \r\n\t") {
			fail(w, http.StatusUnprocessableEntity, "The ntfy address must be an https:// topic URL.")
			return
		}
		if st.ScanNtfy, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(ntfy)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if tok := r.PostFormValue("scan_ntfy_token"); tok != "" {
			if st.ScanNtfyToken, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(tok)); err != nil {
				fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.deps.Store.SaveSettings(r.Context(), st); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "settings.notify", "")
	switch {
	case clear:
		s.flash("The ntfy topic and its access token were removed.")
	case ntfy != "":
		s.flash("The ntfy topic is set: " + ntfy)
	default:
		s.flash("Notification settings saved.")
	}
	hxRedirect(w, "/settings/notify")
}

// saveSMTP replaces the email delivery settings wholesale; a blank password keeps the stored one.
func (s *Server) saveSMTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	host, user := strings.TrimSpace(r.PostFormValue("smtp_host")), strings.TrimSpace(r.PostFormValue("smtp_user"))
	from := strings.TrimSpace(r.PostFormValue("mail_from"))
	var err error
	if from != "" {
		if from, err = gatelogic.NormalizeEmail(from); err != nil {
			fail(w, http.StatusUnprocessableEntity, "MAIL FROM must be a bare email address such as access@example.com")
			return
		}
	}
	port := 587
	if p := strings.TrimSpace(r.PostFormValue("smtp_port")); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			fail(w, http.StatusUnprocessableEntity, "SMTP port "+p+" must be 1-65535")
			return
		}
	}
	if (host == "") != (from == "") {
		fail(w, http.StatusUnprocessableEntity, "Email delivery needs both an SMTP host and a MAIL FROM address; clear both to stop sending.")
		return
	}
	cur, err := s.deps.Store.GetSettings(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	var pass []byte
	if pw := r.PostFormValue("smtp_pass"); host != "" { // clearing the host drops the password too
		switch {
		case pw == "":
			pass = cur.SMTPPass
		case s.deps.Cfg.SecretKey == "":
			fail(w, http.StatusUnprocessableEntity, "Storing an SMTP password needs SERVANAGO_SECRET_KEY (at least 32 characters) in the environment file. Leave the password blank for a relay that does not ask for one.")
			return
		case len(pw) > 1024:
			fail(w, http.StatusUnprocessableEntity, "SMTP password is too long")
			return
		default:
			if pass, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(pw)); err != nil {
				fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	if err := s.deps.Store.SaveSettings(r.Context(), store.Settings{
		SMTPHost: host, SMTPPort: port, SMTPUser: user, SMTPPass: pass, MailFrom: from,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		// the scanner and geo panels below own their own columns: carry them over untouched
		ScanSocket: cur.ScanSocket, ScanHour: cur.ScanHour, ScanNtfy: cur.ScanNtfy, ScanNtfyToken: cur.ScanNtfyToken,
		GeoDB: cur.GeoDB, WebUIMode: cur.WebUIMode, WebUICountries: cur.WebUICountries,
		MailToken: cur.MailToken, MailLMTP: cur.MailLMTP, MailTLS: cur.MailTLS, MailUser: cur.MailUser, MailPass: cur.MailPass,
	}); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("settings saved", "event", "settings.smtp", "ready", host != "")
	s.audit(r, "settings.smtp", "")
	hxRedirect(w, "/settings/email")
}
