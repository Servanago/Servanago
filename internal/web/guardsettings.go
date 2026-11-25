package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/guard"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// guardData is the Protection tab of Settings: ban rules, retention, the bot list and the x402 wallet.
type guardData struct {
	S        store.GuardSettings
	KeySet   bool
	HasKey   bool
	Networks []string
}

func (s *Server) guardSettingsData(ctx context.Context) (guardData, error) {
	g, err := s.deps.Store.GetGuardSettings(ctx)
	if err != nil {
		return guardData{}, err
	}
	return guardData{S: g, KeySet: len(g.X402APIKey) > 0, HasKey: s.deps.Cfg.SecretKey != "", Networks: guard.Networks()}, nil
}

// saveGuardSettings validates and stores the global protection settings, then installs them in the running service.
func (s *Server) saveGuardSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cur, err := s.deps.Store.GetGuardSettings(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	v := r.PostForm
	g := cur
	bad := func(msg string) { fail(w, http.StatusUnprocessableEntity, msg) }
	g.BanCodes = strings.Join(strings.Fields(v.Get("ban_codes")), " ")
	for _, c := range strings.Fields(g.BanCodes) {
		if n, err := strconv.Atoi(c); err != nil || n < 100 || n > 599 {
			bad(fmt.Sprintf("Status code %q: use numbers from 100 to 599, separated by spaces.", c))
			return
		}
	}
	if g.BanCodes == "" {
		bad("Name at least one status code that counts toward a ban.")
		return
	}
	g.BanUnknownHost = v.Get("ban_unknown_host") != ""
	var e1, e2, e3, e4 error
	if g.BanThreshold, e1 = intIn(v, "ban_threshold", 20, 2, 100000); e1 != nil {
		bad("Threshold: a number from 2 to 100000.")
		return
	}
	if g.BanWindowS, e2 = intIn(v, "ban_window_s", 60, 5, 3600); e2 != nil {
		bad("Window: 5 to 3600 seconds.")
		return
	}
	steps := strings.Fields(v.Get("ban_steps_min"))
	if len(steps) == 0 || len(steps) > 8 {
		bad("Escalation steps: one to eight durations in minutes, for example 15 60 1440.")
		return
	}
	for _, st := range steps {
		if n, err := strconv.Atoi(st); err != nil || n < 1 || n > 525600 {
			bad(fmt.Sprintf("Escalation step %q must be minutes from 1 to 525600.", st))
			return
		}
	}
	g.BanStepsMin = strings.Join(steps, " ")
	exempt, err := parseAllowlist(v.Get("ban_exempt"))
	if err != nil {
		bad("Never-ban list: " + err.Error())
		return
	}
	g.BanExempt = exempt
	if g.LogDays, e3 = intIn(v, "log_days", 7, 1, 365); e3 != nil {
		bad("Request log retention: 1 to 365 days.")
		return
	}
	if g.RollupDays, e4 = intIn(v, "rollup_days", 90, 1, 3650); e4 != nil {
		bad("Rollup retention: 1 to 3650 days.")
		return
	}
	g.UAList = strings.Join(strings.Fields(v.Get("ua_list")), " ")
	if len(g.UAList) > 2000 {
		bad("The bot list is too long.")
		return
	}
	if _, ok := v["x402_network"]; ok {
		g.X402Facilitator = strings.TrimSpace(v.Get("x402_facilitator"))
		if g.X402Facilitator != "" {
			if u := g.X402Facilitator; !strings.HasPrefix(u, "https://") || len(u) > 300 || strings.ContainsAny(u, " \r\n\t") {
				bad("The facilitator must be an https:// URL.")
				return
			}
		}
		g.X402Network = v.Get("x402_network")
		if !containsStr(guard.Networks(), g.X402Network) {
			bad("Network: Base (eip155:8453) or Base Sepolia (eip155:84532).")
			return
		}
		g.X402PayTo = strings.TrimSpace(v.Get("x402_pay_to"))
		if g.X402PayTo != "" && !guard.ValidWallet(g.X402PayTo) {
			bad("The wallet must be 0x followed by 40 hex digits.")
			return
		}
		switch key := strings.TrimSpace(v.Get("x402_api_key")); {
		case v.Get("clear_x402_key") != "":
			g.X402APIKey = nil
		case key != "":
			if s.deps.Cfg.SecretKey == "" {
				bad("Storing the facilitator key needs SERVANAGO_SECRET_KEY (at least 32 characters) in the environment file.")
				return
			}
			if g.X402APIKey, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(key)); err != nil {
				fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	if err := s.deps.Store.SaveGuardSettings(r.Context(), g); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.deps.Guard != nil {
		if err := s.deps.Guard.Reload(r.Context(), s.deps.Store, s.deps.Cfg.SecretKey); err != nil {
			fail(w, http.StatusInternalServerError, "Saved, but the running service could not reload: "+err.Error())
			return
		}
	}
	s.audit(r, "settings.protection", "")
	hxRedirect(w, "/settings/guard")
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// setUnderAttack switches a site's under-attack mode on or off; an off site keeps its auto trigger settings.
func (s *Server) setUnderAttack(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("mode")
	if mode != "on" && mode != "off" && mode != "auto" {
		fail(w, http.StatusUnprocessableEntity, "mode must be on, off or auto")
		return
	}
	if !s.mutateSite(w, r, "site.underattack", func(rt *store.Site) error {
		g := ensureGuard(rt)
		if mode == "off" {
			g.UAMode = ""
			return nil
		}
		if mode == "auto" && g.UAAutoRPS == 0 {
			return fmt.Errorf("set the requests-per-second trigger on the Protection tab first")
		}
		if g.CHKind == "turnstile" && (s.deps.Cfg.TurnstileSecret == "" || s.deps.Cfg.TurnstileSiteKey == "") {
			return fmt.Errorf("the Turnstile challenge is not configured; pick proof of work on the Protection tab")
		}
		g.UAMode = mode
		return nil
	}) {
		return
	}
	back := backOf(r, "/sites/"+r.PathValue("id")+"/protection")
	hxRedirect(w, back)
}

// releaseQueue admits everyone to the site for ten minutes (the emergency valve of the access queue).
func (s *Server) releaseQueue(w http.ResponseWriter, r *http.Request) {
	rt, ok := s.gateSite(w, r)
	if !ok {
		return
	}
	if s.deps.Guard == nil {
		fail(w, http.StatusServiceUnavailable, "The protection service is not running.")
		return
	}
	s.deps.Guard.ReleaseQueue(rt.Slug, 10*time.Minute)
	s.audit(r, "queue.release", rt.Hostnames[0])
	hxRedirect(w, backOf(r, "/sites/"+r.PathValue("id")+"/protection"))
}

// checkConnection tests an upstream without saving anything: DNS, TCP, then TLS for https. The answer names the stage that failed.
func (s *Server) checkConnection(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	addrs := []string{}
	host, port := strings.TrimSpace(r.PostFormValue("upstream_host")), strings.TrimSpace(r.PostFormValue("upstream_port"))
	if host != "" && port != "" {
		addrs = append(addrs, host+":"+port)
	}
	addrs = append(addrs, strings.Fields(r.PostFormValue("backends"))...)
	if len(addrs) == 0 {
		fail(w, http.StatusUnprocessableEntity, "Enter an upstream host and port first.")
		return
	}
	if len(addrs) > 17 {
		fail(w, http.StatusUnprocessableEntity, "At most 17 addresses.")
		return
	}
	https, skip := r.PostFormValue("scheme") == "https", r.PostFormValue("tls_skip_verify") != ""
	var b strings.Builder
	for _, a := range addrs {
		b.WriteString(checkOne(r.Context(), a, https, skip))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, b.String())
}

// CheckUpstream is the pure part: the failing stage and a fix hint, or "" when every stage passes.
func CheckUpstream(ctx context.Context, addr string, https, skipVerify bool) (stage, hint string) {
	hostPart, portPart, err := splitAddr(addr)
	if err != nil {
		return "address", "Write it as host:port, for example 192.168.1.20:9200."
	}
	if _, perr := netip.ParseAddr(hostPart); perr != nil {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if _, lerr := (&netResolver{}).lookup(rctx, hostPart); lerr != nil {
			return "DNS lookup", "The name does not resolve from this server. Check the spelling, or use the IP address."
		}
	}
	if err := probe.TCP(ctx, hostPart+":"+portPart, 3*time.Second); err != nil {
		return "TCP connection", "Nothing accepts connections there. Check that the app is running, listens on that address and port, and no firewall blocks this server."
	}
	if https {
		if err := tlsHandshake(ctx, hostPart, portPart, skipVerify); err != nil {
			return "TLS handshake", "The connection works but the certificate or TLS setup fails: " + err.Error() + ". For a self-signed certificate tick 'skip verification'."
		}
	}
	return "", ""
}

func checkOne(ctx context.Context, addr string, https, skip bool) string {
	stage, hint := CheckUpstream(ctx, addr, https, skip)
	if stage == "" {
		return `<p class="ok"><strong>` + htmlEscape(addr) + `</strong>: reachable.</p>`
	}
	return `<p role="alert"><strong>` + htmlEscape(addr) + `</strong>: failed at <em>` + stage + `</em>. ` + htmlEscape(hint) + `</p>`
}
