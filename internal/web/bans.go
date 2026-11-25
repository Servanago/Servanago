package web

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/guard"
	"github.com/servanago/servanago/internal/store"
)

type banRow struct {
	store.Ban
	Active bool
}

type bansData struct {
	Bans   []banRow
	Active int
	Off    bool // the guard service is not running (tests, degraded start)
}

func (s *Server) bansPage(w http.ResponseWriter, r *http.Request) {
	d := bansData{Off: s.deps.Guard == nil}
	now := time.Now().Unix()
	bs, err := s.deps.Store.ListBans(r.Context(), now-7*24*3600)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, b := range bs {
		d.Bans = append(d.Bans, banRow{b, b.Until > now})
		if b.Until > now {
			d.Active++
		}
	}
	s.render(w, "bans", http.StatusOK, page{Title: "Bans", Nav: "bans", Data: d})
}

// createBan bans one address or IPv6 /64 by hand. It refuses the requester's own address.
func (s *Server) createBan(w http.ResponseWriter, r *http.Request) {
	if s.deps.Guard == nil {
		fail(w, http.StatusServiceUnavailable, "The protection service is not running.")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	key, err := guard.ParseClient(r.PostFormValue("client"))
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if me, err := netip.ParseAddr(clientIP(r)); err == nil && guard.Key(me) == key {
		fail(w, http.StatusUnprocessableEntity, "That is your own address: banning it would lock you out.")
		return
	}
	hours, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("hours")))
	if err != nil || hours < 1 || hours > 24*365 {
		fail(w, http.StatusUnprocessableEntity, "Duration: 1 to 8760 hours.")
		return
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if len(reason) > 200 {
		reason = reason[:200]
	}
	actor := "open mode"
	if u, ok := currentUser(r); ok {
		actor = u.Username
	}
	if _, err := s.deps.Guard.Ban(key, "", actor, reason, time.Duration(hours)*time.Hour); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "ban.create", key)
	hxRedirect(w, "/bans")
}

func (s *Server) deleteBan(w http.ResponseWriter, r *http.Request) {
	if s.deps.Guard == nil {
		fail(w, http.StatusServiceUnavailable, "The protection service is not running.")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	client := strings.TrimSpace(r.PostFormValue("client"))
	if err := s.deps.Guard.Unban(client); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "ban.delete", client)
	hxRedirect(w, "/bans")
}
