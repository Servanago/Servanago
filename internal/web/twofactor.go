package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"image/png"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/servanago/servanago/internal/secretbox"
)

const (
	totpPeriod  = 30
	backupCount = 10
	// no 0/o/1/l/i: codes get typed from paper
	backupAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"
)

var (
	totpOpts = totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

	errUnreadable = errors.New("the saved authenticator cannot be decrypted: wrong or missing SERVANAGO_SECRET_KEY. Use a backup code, or run servanago 2fa-reset")
	errNoKey      = errors.New("TOTP needs SERVANAGO_SECRET_KEY to be set")
)

func newBackupCodes() (shown, hashes []string, err error) {
	for range backupCount {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		c := make([]byte, 10)
		for i := range b {
			c[i] = backupAlphabet[int(b[i])%len(backupAlphabet)] // 256 % 31 bias is irrelevant at 50 bits
		}
		shown = append(shown, string(c[:5])+"-"+string(c[5:]))
		hashes = append(hashes, hashCode(string(c)))
	}
	return shown, hashes, nil
}

func normalizeCode(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(s))
}

func hashCode(normalized string) string {
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

func isTOTPCode(c string) bool {
	if len(c) != 6 {
		return false
	}
	for _, r := range c {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// matchStep returns the time step at which code is valid for secret (now +/- one step), or false.
func matchStep(secret, code string, now time.Time) (int64, bool) {
	cur := now.Unix() / totpPeriod
	for step := cur - 1; step <= cur+1; step++ {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*totpPeriod, 0), totpOpts)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// secondFactor checks the user's TOTP or backup code. A TOTP step is accepted once; a backup code once.
func (s *Server) secondFactor(ctx context.Context, uid int64, code string) (bool, error) {
	code = normalizeCode(code)
	if code == "" {
		return false, nil
	}
	if !isTOTPCode(code) {
		return s.deps.Store.UseBackupCode(ctx, uid, hashCode(code))
	}
	t, ok, err := s.deps.Store.GetTOTP(ctx, uid)
	if err != nil || !ok || !t.Enabled {
		return false, err
	}
	secret, err := s.openSeed(t.Secret)
	if err != nil {
		return false, err
	}
	step, ok := matchStep(secret, code, s.auth.now())
	if !ok {
		return false, nil
	}
	return s.deps.Store.AdvanceTOTPStep(ctx, uid, step) // false = replay
}

func (s *Server) openSeed(sealed []byte) (string, error) {
	if s.deps.Cfg.SecretKey == "" {
		return "", errUnreadable
	}
	b, err := secretbox.Open(s.deps.Cfg.SecretKey, sealed)
	if err != nil {
		return "", errUnreadable
	}
	return string(b), nil
}

// warnUnreadableSeed logs at startup when an enrolled seed cannot be opened; the app keeps serving.
func (s *Server) warnUnreadableSeed() {
	if s.deps.Store == nil {
		return
	}
	ctx := context.Background()
	ids, err := s.deps.Store.TOTPUsers(ctx)
	if err != nil {
		return
	}
	for _, id := range ids {
		t, ok, err := s.deps.Store.GetTOTP(ctx, id)
		if err != nil || !ok || !t.Enabled {
			continue
		}
		if _, err := s.openSeed(t.Secret); err != nil {
			slog.Error("totp is enrolled but its seed cannot be decrypted", "user_id", id, "error", err)
		}
	}
}

func (s *Server) loginTOTPPage(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(pendingCookieName)
	if err != nil || !s.auth.pendingLive(c.Value) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "login_totp", http.StatusOK, page{Title: "Second factor"})
}

func (s *Server) loginTOTPSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	c, err := r.Cookie(pendingCookieName)
	if err != nil || !s.auth.pendingLive(c.Value) {
		redirect(w, r, "/login", http.StatusUnauthorized)
		return
	}
	if !s.auth.attempt(ip) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	if !s.auth.tryPending(c.Value) {
		redirect(w, r, "/login", http.StatusUnauthorized)
		return
	}
	uid, _ := s.auth.pendingUser(c.Value) // live: checked above
	u, err := s.deps.Store.GetUser(r.Context(), uid)
	if err != nil {
		redirect(w, r, "/login", http.StatusUnauthorized) // removed since the password step
		return
	}
	code := r.PostFormValue("code")
	ok, err := s.secondFactor(r.Context(), u.ID, code)
	if errors.Is(err, errUnreadable) {
		fail(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err != nil {
		slog.Error("login: second factor", "error", err)
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	if !ok {
		slog.Warn("login failed", "event", "login", "method", "totp", "user", u.Username, "ip", ip)
		s.auditAs(r, u.Username, "login.failed", "totp")
		http.Error(w, "Wrong code.", http.StatusUnauthorized)
		return
	}
	method := "totp"
	if !isTOTPCode(normalizeCode(code)) {
		method = "backup-code"
	}
	slog.Info("login", "event", "login", "method", method, "user", u.Username, "ip", ip)
	s.auditAs(r, u.Username, "login", method)
	s.auth.endPending(c.Value)
	s.auth.clear(ip)
	s.setPending(w, r, "", -1)
	s.setSession(w, r, levelFull, u)
	hxRedirect(w, "/")
}

// reauth demands the password (plus a TOTP or backup code once TOTP is on) before a sensitive change.
// On failure it has already answered.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request) bool {
	ip := clientIP(r)
	if !s.auth.attempt(ip) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return false
	}
	u, signedIn := currentUser(r)
	pw := r.PostFormValue("password")
	if !signedIn || !checkPassword(u, true, pw) {
		// The reason separates a form that sent nothing from a wrong password; only the length of the latter is kept.
		why := "no password sent"
		switch {
		case !signedIn:
			why = "not signed in"
		case pw != "":
			why = fmt.Sprintf("password mismatch, %d bytes", len(pw))
		}
		s.audit(r, "reauth.failed", r.URL.Path+": "+why)
		fail(w, http.StatusUnauthorized, "Wrong password.")
		return false
	}
	if t, ok, err := s.deps.Store.GetTOTP(r.Context(), u.ID); err != nil {
		fail(w, http.StatusInternalServerError, "Internal error.")
		return false
	} else if ok && t.Enabled {
		good, err := s.secondFactor(r.Context(), u.ID, r.PostFormValue("code"))
		if errors.Is(err, errUnreadable) {
			fail(w, http.StatusServiceUnavailable, err.Error())
			return false
		}
		if err != nil || !good {
			s.audit(r, "reauth.failed", r.URL.Path+": wrong code")
			fail(w, http.StatusUnauthorized, "Wrong code.")
			return false
		}
	}
	s.auth.clear(ip)
	return true
}

type securityData struct {
	UserID         int64 // the signed-in admin, for the change-password form
	Limited        bool  // REQUIRE_2FA session that must set up TOTP or a passkey first
	Require2FA     bool
	HasKey         bool
	TOTPEnabled    bool
	BackupLeft     int
	PasskeysOK     bool // this request can use WebAuthn
	Passkeys       []passkeyView
	GateIdentities []gateIdentityView
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	if !s.auth.enabled() {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	u, _ := currentUser(r)
	t, ok, err := s.deps.Store.GetTOTP(ctx, u.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	left, _ := s.deps.Store.CountBackupCodes(ctx, u.ID)
	d := securityData{UserID: u.ID, Limited: s.auth.level(r) == levelEnroll, Require2FA: s.deps.Cfg.Require2FA,
		HasKey: s.deps.Cfg.SecretKey != "", TOTPEnabled: ok && t.Enabled, BackupLeft: left}
	if gs, err := s.gateIdentitiesData(ctx); err == nil {
		d.GateIdentities = gs
	} else {
		slog.Error("gate identities", "error", err)
	}
	d.PasskeysOK = s.rpAllowed(r)
	d.Passkeys, err = s.passkeyViews(r)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, "security", http.StatusOK, page{Title: "Security", Data: d})
}

func (s *Server) fragment(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages["security"].ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render fragment", "fragment", name, "error", err)
	}
}

func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cfg.SecretKey == "" {
		fail(w, http.StatusUnprocessableEntity, errNoKey.Error())
		return
	}
	if !s.reauth(w, r) {
		return
	}
	u, _ := currentUser(r)
	account := u.Username
	if s.deps.Cfg.Host != "" {
		account += "@" + s.deps.Cfg.Host
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "ServanaGo", AccountName: account, Period: totpPeriod,
		Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	sealed, err := secretbox.Seal(s.deps.Cfg.SecretKey, []byte(key.Secret()))
	if err == nil {
		err = s.deps.Store.SaveTOTP(r.Context(), u.ID, sealed)
	}
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	img, err := key.Image(200, 200)
	var buf bytes.Buffer
	if err == nil {
		err = png.Encode(&buf, img)
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.fragment(w, "totp_enroll", map[string]any{
		"Secret": key.Secret(), "URI": template.URL(key.URL()),
		"QR": template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())),
	})
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, _ := currentUser(r)
	t, ok, err := s.deps.Store.GetTOTP(ctx, u.ID)
	if err != nil || !ok || t.Enabled {
		fail(w, http.StatusUnprocessableEntity, "There is no authenticator waiting to be confirmed. Start again.")
		return
	}
	ip := clientIP(r)
	if !s.auth.attempt(ip) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	secret, err := s.openSeed(t.Secret)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	step, good := matchStep(secret, normalizeCode(r.PostFormValue("code")), s.auth.now())
	if !good {
		fail(w, http.StatusUnauthorized, "Wrong code. Check the clock on your phone and try again.")
		return
	}
	shown, hashes, err := newBackupCodes()
	if err == nil {
		err = s.deps.Store.EnableTOTP(ctx, u.ID, step, hashes)
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auth.clear(ip)
	slog.Info("totp enabled", "event", "totp.enabled", "user", u.Username)
	s.audit(r, "totp.enabled", "")
	if s.auth.level(r) == levelEnroll {
		s.setSession(w, r, levelFull, u)
	}
	s.fragment(w, "backup_codes", map[string]any{"Codes": shown, "Done": true})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cfg.Require2FA {
		cu, _ := currentUser(r)
		ps, err := s.deps.Store.ListPasskeys(r.Context(), cu.ID)
		if err != nil {
			fail(w, http.StatusInternalServerError, "Internal error.")
			return
		}
		if len(ps) == 0 {
			fail(w, http.StatusForbidden, "This is your only second factor. Add a passkey first.")
			return
		}
	}
	if !s.reauth(w, r) {
		return
	}
	u, _ := currentUser(r)
	if err := s.deps.Store.DeleteTOTP(r.Context(), u.ID); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("totp disabled", "event", "totp.disabled", "user", u.Username)
	s.audit(r, "totp.disabled", "")
	hxRedirect(w, "/security")
}

func (s *Server) backupRegenerate(w http.ResponseWriter, r *http.Request) {
	u, _ := currentUser(r)
	if _, ok, _ := s.deps.Store.GetTOTP(r.Context(), u.ID); !ok {
		fail(w, http.StatusUnprocessableEntity, "Turn on the authenticator first.")
		return
	}
	if !s.reauth(w, r) {
		return
	}
	shown, hashes, err := newBackupCodes()
	if err == nil {
		err = s.deps.Store.ReplaceBackupCodes(r.Context(), u.ID, hashes)
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, fmt.Sprint(err))
		return
	}
	slog.Info("backup codes regenerated", "event", "backup_codes.regenerated", "user", u.Username)
	s.audit(r, "backup_codes.regenerated", "")
	s.fragment(w, "backup_codes", map[string]any{"Codes": shown})
}

// security gates the /security routes: they only exist once a user does (not in open mode).
func (s *Server) security(h http.HandlerFunc, allowEnroll bool) http.Handler {
	return s.gate(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.enabled() {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}, allowEnroll)
}
