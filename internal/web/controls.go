package web

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/store"
)

// applyControls sets the allowlist and basic-auth fields on r from the form.
// r's current BasicHash is kept when the user stays and no new password is given.
func applyControls(r *store.Route, v url.Values) error {
	var cidrs []string
	for _, line := range strings.Split(strings.ReplaceAll(v.Get("allowlist"), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, aerr := netip.ParseAddr(line)
			if aerr != nil {
				return fmt.Errorf("allowlist: %q is not a CIDR range or IP address", line)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		cidrs = append(cidrs, p.Masked().String())
	}
	r.Allowlist = strings.Join(cidrs, "\n")

	gate := strings.TrimSpace(v.Get("gate_mode"))
	switch gate {
	case "", "acl", "open":
	default:
		return fmt.Errorf("access mode %q is unknown: use none, acl or open", gate)
	}
	r.GateMode = gate

	r.Stream, r.MaxBody = v.Get("stream") != "", 0
	if s := strings.TrimSpace(v.Get("max_body")); s != "" {
		n, err := config.ParseSize(s)
		if err != nil {
			return fmt.Errorf("upload limit: %w", err)
		}
		r.MaxBody = n
	}

	user, pw := strings.TrimSpace(v.Get("basic_user")), v.Get("basic_password")
	switch {
	case user == "":
		r.BasicUser, r.BasicHash = "", ""
	case strings.Contains(user, ":"):
		return fmt.Errorf("basic auth user must not contain ':'")
	case pw != "":
		if len(pw) > 72 {
			return fmt.Errorf("basic auth password must be at most 72 bytes")
		}
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		r.BasicUser, r.BasicHash = user, string(h)
	case r.BasicHash != "":
		r.BasicUser = user // keep the stored hash
	default:
		return fmt.Errorf("basic auth needs a password")
	}
	return nil
}

func (s *Server) toggleRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad route id")
		return
	}
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		cur, err := tx.GetRoute(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "route not found"}
		}
		cur.Enabled = !cur.Enabled
		return tx.UpdateRoute(r.Context(), cur)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}
