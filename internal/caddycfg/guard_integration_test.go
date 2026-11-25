package caddycfg

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/servanago/servanago/internal/caddyguard"
	"github.com/servanago/servanago/internal/caddytest"
	"github.com/servanago/servanago/internal/guard"
	"github.com/servanago/servanago/internal/store"
)

// guardRig loads real Caddy with the given sites and a guard service whose clients all look like 203.0.113.9.
type guardRig struct {
	t     *testing.T
	svc   *guard.Service
	port  int
	hosts []string
	cfg   []byte
}

func newRig(t *testing.T, sites ...store.Site) *guardRig {
	t.Helper()
	storage := caddytest.TempDir(t)
	caddytest.Cleanup(t)
	t.Cleanup(func() { _ = caddy.Stop() })
	svc := guard.New("integration-secret-key-integration-0123", nil)
	guard.Install(svc)
	caddyguard.SetClientOf(func(*http.Request) (netip.Addr, bool) { return netip.MustParseAddr("203.0.113.9"), true })
	t.Cleanup(func() {
		guard.Install(nil)
		caddyguard.SetClientOf(nil)
	})
	o := opts()
	o.Issuer = Internal
	o.HTTPPort, o.HTTPSPort = caddytest.FreePort(t), caddytest.FreePort(t)
	o.StoragePath = storage
	b, err := Render(State{[]store.Domain{}, sites}, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(b, false); err != nil {
		t.Fatalf("caddy rejected the config: %v", err)
	}
	r := &guardRig{t: t, svc: svc, port: o.HTTPSPort, hosts: sites[0].Hostnames, cfg: b}
	caddytest.WaitCert(t, o.HTTPSPort, sites[0].Hostnames[0])
	return r
}

func (g *guardRig) client() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: g.hosts[0]},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", g.port))
			},
		}}
}

type reply struct {
	Code   int
	Body   string
	Header http.Header
	Cookie []*http.Cookie
}

func (g *guardRig) do(method, host, path string, body string, hdr map[string]string, cookies ...*http.Cookie) reply {
	g.t.Helper()
	req, _ := http.NewRequest(method, "https://"+g.hosts[0]+path, strings.NewReader(body))
	req.Host = host
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := g.client().Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, string(b), resp.Header, resp.Cookies()}
}

func (g *guardRig) get(path string, cookies ...*http.Cookie) reply {
	return g.do("GET", g.hosts[0], path, "", nil, cookies...)
}

func proxySite(t *testing.T, host, slug, upstream string, f func(*store.Site)) store.Site {
	_, port, _ := net.SplitHostPort(upstream)
	n, _ := strconv.Atoi(port)
	g := store.DefaultGuard()
	s := store.Site{ID: 2, Slug: slug, Kind: "proxy", Hostnames: []string{host}, Scheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: n, Enabled: true, Guard: &g}
	if f != nil {
		f(&s)
	}
	return s
}

func TestObserverCountsAndUnknownHostIs404(t *testing.T) {
	up := caddytest.Upstream(t, "ok")
	rig := newRig(t, proxySite(t, "obs.test", "obs", up, nil))
	if r := rig.get("/"); r.Code != 200 || r.Body != "ok" {
		t.Fatalf("GET / = %d %q", r.Code, r.Body)
	}
	if r := rig.do("GET", "nobody.test", "/x", "", nil); r.Code != 404 || r.Body != "" {
		t.Errorf("unknown host: %d %q, want an empty 404", r.Code, r.Body)
	}
	rig.svc.Tick(time.Now())
	if got := rig.svc.Live("obs", 30); got.Req != 1 || got.S2 != 1 {
		t.Errorf("site counters: %+v", got)
	}
	if got := rig.svc.Live("", 30); got.Unknown != 1 {
		t.Errorf("unknown-host counter: %+v", got)
	}
}

func TestBanBlocksAfterThresholdAndSurvivesReload(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }))
	defer bad.Close()
	site := proxySite(t, "ban.test", "ban", strings.TrimPrefix(bad.URL, "http://"), func(s *store.Site) { s.Guard.BanOn = true })
	rig := newRig(t, site)
	rig.svc.SetSettings(store.GuardSettings{BanCodes: "403", BanThreshold: 3, BanWindowS: 60, BanStepsMin: "15 60"})
	for i := 0; i < 3; i++ {
		if r := rig.get("/x"); r.Code != 403 {
			t.Fatalf("request %d: %d", i, r.Code)
		}
	}
	r := rig.get("/x")
	if r.Code != 403 || r.Body != "Forbidden\n" {
		t.Fatalf("after the threshold the ban layer must answer: %d %q", r.Code, r.Body)
	}
	// a re-Load (any site save) keeps the ban: it lives in the registry, not in the module
	if err := caddy.Load(rig.cfg, false); err != nil {
		t.Fatal(err)
	}
	if r := rig.get("/x"); r.Body != "Forbidden\n" {
		t.Errorf("after a reload the ban must still hold: %d %q", r.Code, r.Body)
	}
}

var hiddenRE = regexp.MustCompile(`name="(\w+)" value="([^"]*)"`)

func TestChallengeRoundTrip(t *testing.T) {
	up := caddytest.Upstream(t, "secret")
	rig := newRig(t, proxySite(t, "ch.test", "ch", up, func(s *store.Site) {
		s.Guard.UAMode, s.Guard.CHDifficulty, s.Guard.CHTTLMin = "on", "low", 5
	}))
	r := rig.get("/page?x=1")
	if r.Code != 403 || r.Header.Get("X-ServanaGo-Challenge") != "pow" || strings.Contains(r.Body, "secret") {
		t.Fatalf("challenge page: %d %v", r.Code, r.Header)
	}
	form := url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(r.Body, -1) {
		form.Set(m[1], m[2])
	}
	bits, _ := strconv.Atoi(form.Get("bits"))
	for n := 0; ; n++ {
		h := sha256.Sum256([]byte(form.Get("salt") + strconv.Itoa(n)))
		if zeros(h) >= bits {
			form.Set("counter", strconv.Itoa(n))
			break
		}
	}
	form.Set("return", "/page?x=1")
	p := rig.do("POST", "ch.test", guard.ChallengePath, form.Encode(), nil)
	if p.Code != 303 || p.Header.Get("Location") != "/page?x=1" || len(p.Cookie) == 0 {
		t.Fatalf("solve: %d %v", p.Code, p.Header)
	}
	if ok := rig.get("/page", p.Cookie...); ok.Code != 200 || ok.Body != "secret" {
		t.Errorf("with the pass: %d %q", ok.Code, ok.Body)
	}
	if rig.get("/page").Code != 403 {
		t.Error("without the pass the challenge must stay")
	}
}

func zeros(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		for m := byte(0x80); m != 0 && b&m == 0; m >>= 1 {
			n++
		}
		break
	}
	return n
}

func TestQueueHoldsTheSecondVisitorInOrder(t *testing.T) {
	up := caddytest.Upstream(t, "inside")
	rig := newRig(t, proxySite(t, "q.test", "q", up, func(s *store.Site) { s.Guard.QOn, s.Guard.QCapacity = true, 1 }))
	enter := func() []*http.Cookie {
		r := rig.do("GET", "q.test", "/", "", map[string]string{"Accept": "text/html"})
		if r.Code != 302 || len(r.Cookie) == 0 {
			t.Fatalf("first visit: %d", r.Code)
		}
		return r.Cookie
	}
	a, b := enter(), enter()
	ra := rig.get("/", a...)
	if ra.Code != 200 || ra.Body != "inside" {
		t.Fatalf("first visitor: %d %q", ra.Code, ra.Body)
	}
	if rb := rig.get("/", b...); rb.Code != 503 || !strings.Contains(rb.Body, "in line") {
		t.Fatalf("second visitor: %d", rb.Code)
	}
	if st := rig.svc.QueueStats("q"); st.Active != 1 || st.Waiting != 1 {
		t.Errorf("room: %+v", st)
	}
	rig.svc.ReleaseQueue("q", time.Minute)
	if rb := rig.get("/", b...); rb.Code != 200 {
		t.Errorf("release: %d", rb.Code)
	}
}

func TestX402ThroughCaddy(t *testing.T) {
	fac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = json.NewEncoder(w).Encode(map[string]any{"isValid": true, "success": true, "transaction": "0xabc"})
	}))
	defer fac.Close()
	up := caddytest.Upstream(t, "paid content")
	rig := newRig(t, proxySite(t, "pay.test", "pay", up, func(s *store.Site) {
		s.X402 = []store.X402Route{{Path: "/api/", Price: "0.001", Mode: "all", GrantKind: "token", TokenTTLs: 600}}
	}))
	rig.svc.SetX402(guard.X402Config{Facilitator: fac.URL, Network: "eip155:84532", PayTo: "0x1111111111111111111111111111111111111111"})
	if r := rig.get("/free"); r.Code != 200 {
		t.Errorf("unpaid path: %d", r.Code)
	}
	r := rig.get("/api/data")
	if r.Code != 402 || r.Header.Get("PAYMENT-REQUIRED") == "" {
		t.Fatalf("no payment: %d %v", r.Code, r.Header)
	}
	var req struct {
		Accepts []map[string]any `json:"accepts"`
	}
	raw, _ := base64.StdEncoding.DecodeString(r.Header.Get("PAYMENT-REQUIRED"))
	if err := json.Unmarshal(raw, &req); err != nil || len(req.Accepts) != 1 {
		t.Fatalf("requirements: %s %v", raw, err)
	}
	pay, _ := json.Marshal(map[string]any{"x402Version": 2, "accepted": req.Accepts[0], "payload": map[string]any{"signature": "0xs", "authorization": map[string]any{"nonce": "0xn1"}}})
	paid := rig.do("GET", "pay.test", "/api/data", "", map[string]string{"PAYMENT-SIGNATURE": base64.StdEncoding.EncodeToString(pay)})
	if paid.Code != 200 || paid.Body != "paid content" || paid.Header.Get("PAYMENT-RESPONSE") == "" || paid.Header.Get("X-ServanaGo-Access") == "" {
		t.Fatalf("paid: %d %q %v", paid.Code, paid.Body, paid.Header)
	}
	if again := rig.do("GET", "pay.test", "/api/data", "", map[string]string{"X-ServanaGo-Access": paid.Header.Get("X-ServanaGo-Access")}); again.Code != 200 {
		t.Errorf("token access: %d", again.Code)
	}
}

func TestFailoverSkipsADeadBackend(t *testing.T) {
	live := caddytest.Upstream(t, "alive")
	dead := net.JoinHostPort("127.0.0.1", strconv.Itoa(caddytest.FreePort(t)))
	rig := newRig(t, proxySite(t, "fo.test", "fo", live, func(s *store.Site) { s.Guard.Backends = dead }))
	for i := 0; i < 10; i++ {
		if r := rig.get("/"); r.Code != 200 || r.Body != "alive" {
			t.Fatalf("request %d: %d %q (a dead backend must be skipped)", i, r.Code, r.Body)
		}
	}
}

func TestPageSiteAndRedirect(t *testing.T) {
	g := store.DefaultGuard()
	maint := store.Site{ID: 2, Slug: "maint", Kind: "page", Hostnames: []string{"page.test"}, Scheme: "http", Enabled: true, Guard: &g,
		Page: store.SitePage{Status: 503, Title: "Back soon", Message: "Doing {http.request.host} work"}}
	g2 := store.DefaultGuard()
	redir := store.Site{ID: 3, Slug: "redir", Kind: "page", Hostnames: []string{"old.test"}, Scheme: "http", Enabled: true, Guard: &g2,
		Page: store.SitePage{Status: 301, Target: "https://new.example.org/base/", KeepPath: true}}
	rig := newRig(t, maint, redir)
	r := rig.get("/anything")
	if r.Code != 503 || !strings.Contains(r.Body, "Back soon") || strings.Contains(r.Body, "page.test") || !strings.Contains(r.Header.Get("Content-Type"), "text/html") {
		t.Errorf("page: %d %q (braces must stay literal)", r.Code, r.Body)
	}
	rd := rig.do("GET", "old.test", "/a/b?x=1", "", nil)
	if rd.Code != 301 || rd.Header.Get("Location") != "https://new.example.org/base/a/b?x=1" {
		t.Errorf("redirect: %d %q", rd.Code, rd.Header.Get("Location"))
	}
}

// An upgraded connection passes through the observer: the 101 is relayed and bytes flow both ways.
func TestWebSocketStyleUpgradeThroughObserver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n"))
				_, _ = io.Copy(c, br)
			}()
		}
	}()
	rig := newRig(t, proxySite(t, "ws.test", "ws", ln.Addr().String(), nil))
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", rig.port), &tls.Config{InsecureSkipVerify: true, ServerName: "ws.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprint(conn, "GET /sock HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade answer: %q", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through the observer: %q %v", buf, err)
	}
}
