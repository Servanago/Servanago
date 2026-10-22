package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

// refView is one site on the Reference page: the dashboard row plus the two checks the dashboard does not make.
type refView struct {
	siteRow
	Unit      string   // the unit's ActiveState; "" for a site with no unit or when the helper did not answer
	Health    string   // ok | issue | disabled
	Issues    []string // why Health is issue
	RootErr   string   // why the folder cannot be read, or ""
	NotesLong bool     // more than the card shows without "Show all"
	Filter    string   // lower-case hostnames, slug and kind: what the search box matches
}

// healthOf names every reason an enabled site needs attention. A disabled site serves nothing, so it has none.
// A runtime site whose unit state could not be read counts: nobody knows it is fine.
func healthOf(r siteRow, unit string, unitErr, rootErr error) (string, []string) {
	if !r.Enabled {
		return "disabled", nil
	}
	var issues []string
	if r.Upstream == "down" {
		issues = append(issues, "upstream down")
	}
	if r.Cert.State == probe.StateError {
		issues = append(issues, "certificate error")
	}
	if st := r.DNSState(); st == "error" || st == "conflict" {
		issues = append(issues, "DNS "+st)
	}
	if rootErr != nil {
		issues = append(issues, "folder not readable")
	}
	if r.IsRuntime() {
		switch {
		case unitErr != nil:
			issues = append(issues, "status unavailable")
		case unit != "active":
			issues = append(issues, "unit "+unit)
		}
	}
	if len(issues) > 0 {
		return "issue", issues
	}
	return "ok", nil
}

// unitState is the helper's ActiveState for the site's unit (its socket for a socket-activated one).
func (s *Server) unitState(ctx context.Context, rt store.Site) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := s.helperClient().Call(ctx, helper.ActionUnitStatus, helper.Spec{Slug: rt.Slug})
	if err != nil {
		return "", err
	}
	if st.Status == nil {
		return "", errors.New("no status")
	}
	return st.Status.ActiveState, nil
}

// folderErr is the check the edit page makes: Caddy (or the app's user) must be able to enter the folder.
func folderErr(rt store.Site) error {
	if rt.Kind == "proxy" || rt.Kind == "static" && rt.SiteUser != "" { // a user's static site is read by its own unit
		return nil
	}
	return config.StaticRootReadable(rt.WebRoot())
}

func (s *Server) referencePage(w http.ResponseWriter, r *http.Request) {
	rows, err := s.siteRows(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]refView, len(rows))
	errs := make([]error, len(rows))
	probe.Parallel(len(rows), func(i int) { // each goroutine writes only its own slot
		views[i].siteRow = rows[i]
		if rows[i].IsRuntime() && rows[i].Enabled {
			views[i].Unit, errs[i] = s.unitState(r.Context(), rows[i].Site)
		}
	})
	var kinds, users, phps []string
	helperDown, runtime := true, false
	for i := range views {
		v := &views[i]
		rootErr := folderErr(v.Site)
		if rootErr != nil {
			v.RootErr = rootErr.Error()
		}
		v.Health, v.Issues = healthOf(v.siteRow, v.Unit, errs[i], rootErr)
		if v.IsRuntime() && v.Enabled {
			runtime = true
			helperDown = helperDown && errs[i] != nil
		}
		v.NotesLong = len(v.Notes) > 600
		v.Filter = strings.ToLower(strings.Join(v.Hostnames, " ") + " " + v.Slug + " " + v.Kind)
		kinds, users, phps = addUnique(kinds, v.Kind), addUnique(users, v.SiteUser), addUnique(phps, v.FPMVersion)
	}
	slices.Sort(kinds)
	slices.Sort(users)
	slices.Sort(phps)
	s.render(w, "reference", http.StatusOK, page{Title: "Reference", Data: struct {
		Rows               []refView
		Kinds, Users, PHPs []string
		HelperDown         bool
	}{views, kinds, users, phps, runtime && helperDown}})
}

// addUnique appends v unless it is empty or already there.
func addUnique(list []string, v string) []string {
	if v == "" || slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// Target is where the site's content comes from: its upstream, socket or folder.
func (v refView) Target() string {
	switch v.Kind {
	case "proxy", "node", "frankenphp":
		return v.UpstreamHost + ":" + strconv.Itoa(v.UpstreamPort)
	case "fastcgi":
		if v.UpstreamPort != 0 {
			return net.JoinHostPort(v.UpstreamHost, strconv.Itoa(v.UpstreamPort))
		}
		return v.UpstreamHost
	}
	return v.WebRoot()
}

// Updated is the date part of the last save, for the card.
func (v refView) Updated() string { return strings.SplitN(v.UpdatedAt, "T", 2)[0] }
