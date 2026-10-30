package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// applyControls sets the editor form's tuning and access fields on r from the form. Each block is
// applied only when the form actually carries it: the Gate tab owns allowlist, basic auth and the
// gate mode now, and a save of the editor must not reset what it no longer shows.
// r's current BasicHash is kept when the user stays and no new password is given.
func applyControls(r *store.Site, v url.Values) error {
	if _, ok := v["allowlist"]; ok {
		a, err := parseAllowlist(v.Get("allowlist"))
		if err != nil {
			return err
		}
		r.Allowlist = a
	}
	if _, ok := v["gate_mode"]; ok {
		gate := strings.TrimSpace(v.Get("gate_mode"))
		switch gate {
		case "", "acl", "open":
		default:
			return fmt.Errorf("access mode %q is unknown: use none, acl or open", gate)
		}
		r.GateMode = gate
	}
	if _, ok := v["stream"]; ok {
		r.Stream = v.Get("stream") != ""
	}
	if _, ok := v["max_body"]; ok {
		r.MaxBody = 0
		if s := strings.TrimSpace(v.Get("max_body")); s != "" {
			n, err := config.ParseSize(s)
			if err != nil {
				return fmt.Errorf("upload limit: %w", err)
			}
			r.MaxBody = n
		}
	}
	if _, ok := v["basic_user"]; ok {
		if err := applyBasicAuth(r, strings.TrimSpace(v.Get("basic_user")), v.Get("basic_password")); err != nil {
			return err
		}
	}
	return nil
}

// parseAllowlist normalizes a newline-separated CIDR list (single addresses allowed).
func parseAllowlist(text string) (string, error) {
	var cidrs []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, aerr := netip.ParseAddr(line)
			if aerr != nil {
				return "", fmt.Errorf("allowlist: %q is not a CIDR range or IP address", line)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		cidrs = append(cidrs, p.Masked().String())
	}
	return strings.Join(cidrs, "\n"), nil
}

// applyBasicAuth sets user and hash from the form pair.
func applyBasicAuth(r *store.Site, user, pw string) error {
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

func (s *Server) toggleSite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return
	}
	host := ""
	var toggled store.Site
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		cur, err := tx.GetSite(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "site not found"}
		}
		host = cur.Hostnames[0]
		cur.Enabled = !cur.Enabled
		toggled = cur
		return tx.UpdateSite(r.Context(), cur)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "site.toggled", host)
	if err := s.runtimeApply(r, toggled); err != nil { // starts or stops the site's unit
		slog.Error("runtime site toggle", "slug", toggled.Slug, "error", err)
	}
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}
