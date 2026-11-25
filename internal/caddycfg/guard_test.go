package caddycfg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

// handlerNames lists the handler ids of a site's subroute in order, descending into nothing: one entry per route handle.
func chainOf(t *testing.T, cfg []byte, host string) []string {
	t.Helper()
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match  []struct{ Host []string }
						Handle []map[string]any
					}
				}
			}
		}
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Apps.HTTP.Servers["srv0"].Routes {
		if len(r.Match) == 0 || r.Match[0].Host[0] != host {
			continue
		}
		var names []string
		sub, _ := r.Handle[0]["routes"].([]any)
		for _, x := range sub {
			for _, h := range x.(map[string]any)["handle"].([]any) {
				names = append(names, h.(map[string]any)["handler"].(string))
			}
		}
		return names
	}
	t.Fatalf("no route for %s", host)
	return nil
}

func TestEveryGuardLayerRendersInTheDesignedOrder(t *testing.T) {
	g := store.DefaultGuard()
	g.BanOn, g.UAMode, g.QOn = true, "on", true
	st := with(site, func(r *store.Site) {
		r.Slug, r.Guard = "ordered", &g
		r.CountryMode, r.Countries, r.Waf, r.BasicUser, r.BasicHash = "deny", "DE", "crs", "u", "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
		r.X402 = []store.X402Route{{Path: "/api/", Price: "0.01", Mode: "all", GrantKind: "request", TokenTTLs: 600}}
	})
	b, err := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(chainOf(t, b, st.Hostnames[0]), " ")
	want := "servanago_traffic servanago_ban servanago_geoip waf servanago_challenge authentication servanago_x402 servanago_queue reverse_proxy"
	if got != want {
		t.Errorf("layer order:\n got  %s\n want %s", got, want)
	}
}

func TestEveryEnabledSiteIsObserved(t *testing.T) {
	b, err := Render(State{[]store.Domain{dom}, []store.Site{site}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if names := chainOf(t, b, site.Hostnames[0]); names[0] != "servanago_traffic" {
		t.Errorf("a plain site must start with the observer: %v", names)
	}
}

func TestAllowlist403IsLabelledBlocked(t *testing.T) {
	st := with(site, func(r *store.Site) { r.Allowlist = "10.0.0.0/8" })
	b, _ := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts())
	if !strings.Contains(string(b), `"sg_outcome":"blocked"`) {
		t.Error("the allowlist's 403 must set the outcome so the traffic page counts it as blocked")
	}
}

func TestCatchAllIsLastAndAnswers404(t *testing.T) {
	b, _ := Render(State{[]store.Domain{dom}, []store.Site{site}}, opts())
	var c struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match  []any
						Handle []map[string]any
					}
				}
			}
		}
	}
	_ = json.Unmarshal(b, &c)
	rs := c.Apps.HTTP.Servers["srv0"].Routes
	last := rs[len(rs)-1]
	if len(last.Match) != 0 || last.Handle[0]["handler"] != "servanago_traffic" || last.Handle[len(last.Handle)-1]["status_code"] != "404" {
		t.Errorf("catch-all: %+v", last)
	}
}

func TestFailoverRendersOnlyWithMoreThanOneBackend(t *testing.T) {
	one, _ := Render(State{[]store.Domain{dom}, []store.Site{site}}, opts())
	if strings.Contains(string(one), "load_balancing") {
		t.Error("a single backend must not render balancing")
	}
	g := store.DefaultGuard()
	g.Backends = "10.0.0.2:9000\n10.0.0.3:9000"
	two, _ := Render(State{[]store.Domain{dom}, []store.Site{with(site, func(r *store.Site) { r.Guard = &g })}}, opts())
	for _, want := range []string{"load_balancing", "round_robin", "unhealthy_status", "10.0.0.3:9000"} {
		if !strings.Contains(string(two), want) {
			t.Errorf("failover config lacks %q", want)
		}
	}
	// only proxy sites balance
	st := with(asStatic(site, "/srv/www/x"), func(r *store.Site) { r.Guard = &g })
	if s, _ := Render(State{[]store.Domain{dom}, []store.Site{st}}, opts()); strings.Contains(string(s), "load_balancing") {
		t.Error("a static site rendered balancing")
	}
}

func TestPageSiteRendersStatusRedirectAndEscapesBraces(t *testing.T) {
	g := store.DefaultGuard()
	page := with(site, func(r *store.Site) {
		r.Kind, r.UpstreamHost, r.UpstreamPort, r.Guard = "page", "", 0, &g
		r.Page = store.SitePage{Status: 503, HTML: "<p>{http.request.header.Authorization}</p>"}
	})
	b, err := Render(State{[]store.Domain{dom}, []store.Site{page}}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `\\{http.request.header.Authorization}`) {
		t.Errorf("custom HTML must reach Caddy with escaped braces: %s", b)
	}
	redir := with(page, func(r *store.Site) {
		r.Page = store.SitePage{Status: 308, Target: "https://new.example.org/", KeepPath: true}
	})
	b, _ = Render(State{[]store.Domain{dom}, []store.Site{redir}}, opts())
	if !strings.Contains(string(b), `https://new.example.org{http.request.uri}`) || !strings.Contains(string(b), `"status_code":"308"`) {
		t.Errorf("redirect: %s", b)
	}
}
