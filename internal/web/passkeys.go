package web

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/servanago/servanago/internal/store"
)

const (
	maxPasskeys    = 10
	maxPasskeyName = 100
	maxCredBody    = 64 << 10
)

// waUser is one admin as WebAuthn sees them. The handle is the user's random id, stable for their lifetime.
type waUser struct {
	user  store.User
	creds []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return u.user.WebAuthnID }
func (u waUser) WebAuthnName() string                       { return u.user.Username }
func (u waUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

var errNoRP = errors.New("passkeys work only on https://" + "<SERVANAGO_HOST> or on localhost")

// relyingParty builds the WebAuthn config for this request. RP ID is the request hostname, accepted only when it is
// SERVANAGO_HOST (over TLS) or localhost (a secure context, for on-box recovery). Origin keeps the port.
func (s *Server) relyingParty(r *http.Request) (wa *webauthn.WebAuthn, rpID string, err error) {
	host := hostOf(r)
	scheme := "https"
	switch {
	case s.deps.Cfg.Host != "" && host == strings.ToLower(s.deps.Cfg.Host):
		if !secureRequest(r) {
			return nil, "", errNoRP
		}
	case host == "localhost":
		if !secureRequest(r) {
			scheme = "http"
		}
	default:
		return nil, "", errNoRP
	}
	wa, err = webauthn.New(&webauthn.Config{RPID: host, RPDisplayName: "ServanaGo", RPOrigins: []string{scheme + "://" + r.Host}})
	return wa, host, err
}

func (s *Server) rpAllowed(r *http.Request) bool {
	_, _, err := s.relyingParty(r)
	return err == nil
}

// passkeysOffered: show the login button only when this request can use WebAuthn and a passkey exists for it.
func (s *Server) passkeysOffered(r *http.Request) bool {
	_, rp, err := s.relyingParty(r)
	if err != nil {
		return false
	}
	has, err := s.deps.Store.HasPasskeyFor(r.Context(), rp)
	return err == nil && has
}

// loadUser returns user with the credentials they registered for rpID.
func (s *Server) loadUser(r *http.Request, user store.User, rpID string) (waUser, error) {
	ps, err := s.deps.Store.ListPasskeys(r.Context(), user.ID)
	if err != nil {
		return waUser{}, err
	}
	u := waUser{user: user}
	for _, p := range ps {
		if p.RPID != rpID {
			continue
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(p.Credential), &c); err != nil {
			return waUser{}, err
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

type passkeyView struct {
	ID, Name, CreatedAt, LastUsedAt string
	OtherHost                       bool // registered for a different host: kept, never matches here
}

func (s *Server) passkeyViews(r *http.Request) ([]passkeyView, error) {
	_, rp, _ := s.relyingParty(r)
	cu, _ := currentUser(r)
	ps, err := s.deps.Store.ListPasskeys(r.Context(), cu.ID)
	if err != nil {
		return nil, err
	}
	out := make([]passkeyView, 0, len(ps))
	for _, p := range ps {
		out = append(out, passkeyView{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt, OtherHost: p.RPID != rp})
	}
	return out, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readCred(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, maxCredBody))
}

func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	wa, rp, err := s.relyingParty(r)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if !s.reauth(w, r) {
		return
	}
	cu, _ := currentUser(r)
	u, err := s.loadUser(r, cu, rp)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	all, _ := s.deps.Store.ListPasskeys(r.Context(), cu.ID)
	if len(all) >= maxPasskeys {
		fail(w, http.StatusUnprocessableEntity, "Passkey limit reached. Delete one first.")
		return
	}
	excl := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		excl = append(excl, c.Descriptor())
	}
	creation, sd, err := wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}),
		webauthn.WithExclusions(excl))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, ok := s.auth.putCeremony("register", *sd)
	if !ok {
		fail(w, http.StatusTooManyRequests, "Too many passkey requests in progress. Try again in a few minutes.")
		return
	}
	writeJSON(w, map[string]any{"id": id, "options": creation.Response})
}

func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	wa, rp, err := s.relyingParty(r)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	sd, ok := s.auth.takeCeremony(r.URL.Query().Get("id"), "register")
	if !ok {
		fail(w, http.StatusUnauthorized, "That passkey request expired. Start again.")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "passkey"
	}
	if len(name) > maxPasskeyName {
		fail(w, http.StatusUnprocessableEntity, "Name too long.")
		return
	}
	cu, _ := currentUser(r)
	u, err := s.loadUser(r, cu, rp)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	raw, err := readCred(r)
	if err != nil {
		fail(w, http.StatusBadRequest, "Unreadable passkey response.")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(raw)
	if err != nil {
		fail(w, http.StatusBadRequest, "Unreadable passkey response.")
		return
	}
	cred, err := wa.CreateCredential(u, sd, parsed)
	if err != nil {
		slog.Warn("passkey registration rejected", "error", err)
		fail(w, http.StatusUnprocessableEntity, "The passkey could not be verified.")
		return
	}
	js, err := json.Marshal(cred)
	if err == nil {
		err = s.deps.Store.AddPasskey(r.Context(), cu.ID, store.Passkey{ID: randToken(), RPID: rp, CredentialID: cred.ID, Credential: string(js), Name: name})
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("passkey added", "event", "passkey.added", "user", cu.Username, "rp", rp)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	cu, _ := currentUser(r)
	ok, err := s.deps.Store.DeletePasskey(r.Context(), cu.ID, r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		fail(w, http.StatusNotFound, "No such passkey.")
		return
	}
	slog.Info("passkey removed", "event", "passkey.removed", "user", cu.Username)
	hxRedirect(w, "/security")
}

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	wa, _, err := s.relyingParty(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.auth.attempt("pk:" + clientIP(r)) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	as, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	id, ok := s.auth.putCeremony("login", *sd)
	if !ok {
		http.Error(w, "Busy. Try again in a few minutes.", http.StatusTooManyRequests)
		return
	}
	writeJSON(w, map[string]any{"id": id, "options": as.Response})
}

// passkeyLoginFinish: every failure is the same 401, so a caller learns nothing about why.
func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	deny := func(why string, err error) {
		slog.Warn("login failed", "event", "login", "method", "passkey", "ip", ip, "why", why, "error", err)
		http.Error(w, "Passkey sign-in failed.", http.StatusUnauthorized)
	}
	wa, rp, err := s.relyingParty(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.auth.attempt("pk:" + ip) {
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	sd, ok := s.auth.takeCeremony(r.URL.Query().Get("id"), "login")
	if !ok {
		deny("no ceremony", nil)
		return
	}
	raw, err := readCred(r)
	if err != nil {
		deny("read", err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		deny("parse", err)
		return
	}
	handler := func(_, handle []byte) (webauthn.User, error) {
		user, found, err := s.deps.Store.GetUserByWebAuthnID(r.Context(), handle)
		if err != nil || !found {
			return nil, errors.New("unknown user handle")
		}
		return s.loadUser(r, user, rp) // only this user's own credentials can validate
	}
	wu, cred, err := wa.ValidatePasskeyLogin(handler, sd, parsed)
	if err != nil {
		deny("validate", err)
		return
	}
	user := wu.(waUser).user
	if cred.Authenticator.CloneWarning {
		deny("clone warning", nil)
		return
	}
	js, err := json.Marshal(cred)
	if err == nil {
		err = s.deps.Store.TouchPasskey(r.Context(), cred.ID, string(js))
	}
	if err != nil {
		slog.Error("passkey login: save", "error", err)
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	s.auth.clear("pk:" + ip)
	slog.Info("login", "event", "login", "method", "passkey", "user", user.Username, "ip", ip)
	s.setSession(w, r, levelFull, user)
	hxRedirect(w, "/")
}
