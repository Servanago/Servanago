package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

type userView struct {
	ID          int64
	Username    string
	CreatedAt   string
	LastLoginAt string
	You         bool
	TOTP        bool
	Passkeys    int
}

type usersData struct {
	Users    []userView
	NeedCode bool // the signed-in admin has an authenticator, so actions ask for a code too
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	me, _ := currentUser(r)
	us, err := s.deps.Store.ListUsers(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	d := usersData{}
	for _, u := range us {
		v := userView{ID: u.ID, Username: u.Username, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt, You: u.ID == me.ID}
		if t, ok, err := s.deps.Store.GetTOTP(ctx, u.ID); err == nil {
			v.TOTP = ok && t.Enabled
		}
		if ps, err := s.deps.Store.ListPasskeys(ctx, u.ID); err == nil {
			v.Passkeys = len(ps)
		}
		if v.You {
			d.NeedCode = v.TOTP
		}
		d.Users = append(d.Users, v)
	}
	s.render(w, "users", http.StatusOK, page{Title: "Users", Data: d})
}

// target reads {id} and loads the user, answering 400 or 404 itself on failure.
func (s *Server) target(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad user id")
		return store.User{}, false
	}
	u, err := s.deps.Store.GetUser(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "No such user.")
		return store.User{}, false
	}
	return u, true
}

// hashPassword checks the password rules and returns the bcrypt hash of the trimmed password; on failure it has answered 422.
func hashPassword(w http.ResponseWriter, pw string) (string, bool) {
	pw = strings.TrimSpace(pw)
	if err := config.ValidatePassword(pw); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return "", false
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return "", false
	}
	return string(h), true
}

// addUser creates another admin. Like every action here it re-authenticates the acting admin first: a stolen
// session must not be able to mint a second way in.
func (s *Server) addUser(w http.ResponseWriter, r *http.Request) {
	if !s.reauth(w, r) {
		return
	}
	me, _ := currentUser(r)
	name := normalizeUsername(r.PostFormValue("username"))
	if err := config.ValidateUsername(name); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	hash, ok := hashPassword(w, r.PostFormValue("new_password"))
	if !ok {
		return
	}
	if _, exists, err := s.deps.Store.GetUserByName(r.Context(), name); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	} else if exists {
		fail(w, http.StatusConflict, "That username is already taken.")
		return
	}
	if _, err := s.deps.Store.CreateUser(r.Context(), name, hash); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("user added", "event", "user.added", "actor", me.Username, "user", name)
	s.audit(r, "user.added", name)
	hxRedirect(w, "/users")
}

// setPassword replaces a user's password and ends their sessions. For the acting admin's own account the current
// browser gets a fresh session so the change does not sign it out.
func (s *Server) setPassword(w http.ResponseWriter, r *http.Request) {
	if !s.reauth(w, r) {
		return
	}
	t, ok := s.target(w, r)
	if !ok {
		return
	}
	hash, ok := hashPassword(w, r.PostFormValue("new_password"))
	if !ok {
		return
	}
	if err := s.deps.Store.SetPassword(r.Context(), t.ID, hash); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	me, _ := currentUser(r)
	slog.Info("password set", "event", "user.password", "actor", me.Username, "user", t.Username)
	s.audit(r, "user.password", t.Username)
	if t.ID == me.ID {
		fresh, err := s.deps.Store.GetUser(r.Context(), me.ID)
		if err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.setSession(w, r, levelFull, fresh)
		hxRedirect(w, "/security")
		return
	}
	hxRedirect(w, "/users")
}

// resetSecondFactor removes another admin's authenticator, backup codes and passkeys and ends their sessions,
// so their password works alone again. Your own factors are managed on the Security page.
func (s *Server) resetSecondFactor(w http.ResponseWriter, r *http.Request) {
	if !s.reauth(w, r) {
		return
	}
	t, ok := s.target(w, r)
	if !ok {
		return
	}
	me, _ := currentUser(r)
	if t.ID == me.ID {
		fail(w, http.StatusUnprocessableEntity, "Manage your own authenticator and passkeys on the Security page.")
		return
	}
	if _, _, _, err := s.deps.Store.ResetAuth(r.Context(), t.ID); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.deps.Store.BumpEpoch(r.Context(), t.ID); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("second factor reset", "event", "user.2fa_reset", "actor", me.Username, "user", t.Username)
	s.audit(r, "user.2fa_reset", t.Username)
	hxRedirect(w, "/users")
}

// removeUser deletes another admin; their sessions die with them. You cannot remove yourself, and the store
// refuses to remove the last admin.
func (s *Server) removeUser(w http.ResponseWriter, r *http.Request) {
	if !s.reauth(w, r) {
		return
	}
	t, ok := s.target(w, r)
	if !ok {
		return
	}
	me, _ := currentUser(r)
	if t.ID == me.ID {
		fail(w, http.StatusUnprocessableEntity, "You cannot remove yourself. Ask another administrator.")
		return
	}
	if err := s.deps.Store.DeleteUser(r.Context(), t.ID); errors.Is(err, store.ErrLastAdmin) {
		fail(w, http.StatusConflict, err.Error())
		return
	} else if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("user removed", "event", "user.removed", "actor", me.Username, "user", t.Username)
	s.audit(r, "user.removed", t.Username)
	hxRedirect(w, "/users")
}
