package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/alerts"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

type destRow struct {
	store.AlertDest
	EventList []string
}

type alertsData struct {
	Dests     []destRow
	Kinds     []string
	Events    []string
	HasKey    bool
	MailReady bool
}

func (s *Server) alertsPage(w http.ResponseWriter, r *http.Request) {
	ds, err := s.deps.Store.ListAlertDests(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	d := alertsData{Kinds: alerts.Kinds, Events: alerts.Events, HasKey: s.deps.Cfg.SecretKey != ""}
	for _, x := range ds {
		d.Dests = append(d.Dests, destRow{x, strings.Fields(x.Events)})
	}
	if set, err := s.deps.Store.GetSettings(r.Context()); err == nil {
		d.MailReady = set.MailReady()
	}
	s.render(w, "alerts", http.StatusOK, page{Title: "Alerts", Nav: "alerts", Data: d})
}

// defaultEvents is what a new destination listens to: free channels everything, paid ones only the loud events.
func defaultEvents(kind string) []string {
	if kind == "pushover" || kind == "twilio" {
		return []string{"underattack", "x402"}
	}
	return alerts.Events
}

func (s *Server) createAlertDest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	kind, name := r.PostFormValue("kind"), strings.TrimSpace(r.PostFormValue("name"))
	target, secret := strings.TrimSpace(r.PostFormValue("target")), strings.TrimSpace(r.PostFormValue("secret"))
	if s.deps.Cfg.SecretKey == "" {
		fail(w, http.StatusUnprocessableEntity, "Storing a destination needs SERVANAGO_SECRET_KEY (at least 32 characters) in the environment file.")
		return
	}
	if name == "" || len(name) > 60 {
		fail(w, http.StatusUnprocessableEntity, "Give the destination a name of up to 60 characters.")
		return
	}
	if !slices.Contains(alerts.Kinds, kind) {
		fail(w, http.StatusUnprocessableEntity, "Pick a destination kind.")
		return
	}
	if err := alerts.ValidateTarget(kind, target, secret); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	events := defaultEvents(kind)
	if _, ok := r.PostForm["event"]; ok {
		events = nil
		for _, e := range r.PostForm["event"] {
			if slices.Contains(alerts.Events, e) && !slices.Contains(events, e) {
				events = append(events, e)
			}
		}
		if len(events) == 0 {
			fail(w, http.StatusUnprocessableEntity, "Tick at least one event.")
			return
		}
	}
	d := store.AlertDest{Name: name, Kind: kind, Events: strings.Join(events, " "), Enabled: true}
	var err error
	if d.Target, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(target)); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if secret != "" {
		if d.Secret, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(secret)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if _, err := s.deps.Store.CreateAlertDest(r.Context(), d); err != nil {
		fail(w, http.StatusUnprocessableEntity, "That name is already used.")
		return
	}
	s.audit(r, "alert.create", name)
	hxRedirect(w, "/alerts")
}

func (s *Server) destByID(w http.ResponseWriter, r *http.Request) (store.AlertDest, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad destination id")
		return store.AlertDest{}, false
	}
	d, err := s.deps.Store.GetAlertDest(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "destination not found")
		return store.AlertDest{}, false
	}
	return d, true
}

func (s *Server) toggleAlertDest(w http.ResponseWriter, r *http.Request) {
	d, ok := s.destByID(w, r)
	if !ok {
		return
	}
	if err := s.deps.Store.SetAlertDestEnabled(r.Context(), d.ID, !d.Enabled); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "alert.toggle", d.Name)
	hxRedirect(w, "/alerts")
}

func (s *Server) deleteAlertDest(w http.ResponseWriter, r *http.Request) {
	d, ok := s.destByID(w, r)
	if !ok {
		return
	}
	if err := s.deps.Store.DeleteAlertDest(r.Context(), d.ID); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "alert.delete", d.Name)
	hxRedirect(w, "/alerts")
}

// testAlertDest sends one message to the destination and reports the result in place (and on the row).
func (s *Server) testAlertDest(w http.ResponseWriter, r *http.Request) {
	d, ok := s.destByID(w, r)
	if !ok {
		return
	}
	snd := s.deps.Alerts
	if snd == nil {
		snd = &alerts.Sender{Mail: alerts.MailSource(s.deps.Store, s.deps.Cfg.SecretKey)}
	}
	open, err := alerts.Open(s.deps.Cfg.SecretKey, d)
	if err == nil {
		err = snd.Send(r.Context(), open, alerts.Event{Kind: "test", Title: "ServanaGo test", Text: "This is a test message from the Alerts page."})
	}
	alerts.StoreResult(s.deps.Store)(open, err)
	s.audit(r, "alert.test", d.Name)
	if err != nil {
		fail(w, http.StatusBadGateway, "The test failed: "+err.Error())
		return
	}
	inplace(w, "Sent. Check the destination.")
}

// destOptions lists the destinations for a site's override picker, marking the chosen ones.
type destOpt struct {
	ID   int64
	Name string
	On   bool
}

func (s *Server) destOptions(ctx context.Context, chosen []int64) []destOpt {
	ds, err := s.deps.Store.ListAlertDests(ctx)
	if err != nil {
		return nil
	}
	out := make([]destOpt, 0, len(ds))
	for _, d := range ds {
		out = append(out, destOpt{d.ID, d.Name, slices.Contains(chosen, d.ID)})
	}
	return out
}

// fireAlert delivers an event right now to the destinations that listen for it (scan hits, from a request-less goroutine).
func (s *Server) fireAlert(ctx context.Context, ev alerts.Event) {
	snd := s.deps.Alerts
	if snd == nil {
		snd = &alerts.Sender{Mail: alerts.MailSource(s.deps.Store, s.deps.Cfg.SecretKey)}
	}
	n := alerts.NewNotifier(snd)
	n.Resolve = alerts.StoreResolver(s.deps.Store, s.deps.Cfg.SecretKey)
	n.Result = alerts.StoreResult(s.deps.Store)
	n.Fire(ctx, ev)
}
