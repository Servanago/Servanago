package guard

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const wallet = "0x1111111111111111111111111111111111111111"

func paymentHeader(t *testing.T, s *Service, nonce, amount string) string {
	t.Helper()
	conf := s.x402cfg()
	a := assets[conf.Network]
	p := map[string]any{"x402Version": 2,
		"accepted": map[string]any{"scheme": "exact", "network": conf.Network, "amount": amount, "asset": a.Address, "payTo": conf.PayTo, "maxTimeoutSeconds": 60},
		"payload":  map[string]any{"signature": "0xsig" + nonce, "authorization": map[string]any{"nonce": nonce}}}
	b, _ := json.Marshal(p)
	return base64.StdEncoding.EncodeToString(b)
}

type fac struct {
	mu                    sync.Mutex
	verifies, settles     int
	verifyValid, settleOK bool
	down                  bool
}

func (f *fac) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		http.Error(w, "boom", 502)
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
	switch r.URL.Path {
	case "/verify":
		f.verifies++
		_ = json.NewEncoder(w).Encode(map[string]any{"isValid": f.verifyValid, "invalidReason": "bad_sig"})
	case "/settle":
		f.settles++
		_ = json.NewEncoder(w).Encode(map[string]any{"success": f.settleOK, "transaction": "0xabc", "errorReason": "no_funds"})
	}
}

func setup(t *testing.T, f *fac) (*Service, X402Cfg) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s, _ := newSvc(t)
	s.SetX402(X402Config{Facilitator: srv.URL, Network: "eip155:84532", PayTo: wallet})
	return s, X402Cfg{Slug: "site", Routes: []X402Route{{Path: "/api/", Price: "0.001", Mode: "all", Grant: "token", TTL: 600}}}
}

func call(s *Service, cfg X402Cfg, hdr string, extra func(*http.Request)) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://x.test/api/data", nil)
	if hdr != "" {
		req.Header.Set(hdrSignature, hdr)
	}
	if extra != nil {
		extra(req)
	}
	w, handled := s.X402(rec, req, cfg, "1.2.3.4", netip.Addr{}, false)
	if !handled {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("paid content"))
	}
	return rec
}

func TestX402PaymentFlow(t *testing.T) {
	f := &fac{verifyValid: true, settleOK: true}
	s, cfg := setup(t, f)

	rec := call(s, cfg, "", nil)
	if rec.Code != 402 || rec.Header().Get(hdrRequired) == "" || rec.Body.String() == "paid content" {
		t.Fatalf("no payment: %d", rec.Code)
	}
	raw, _ := base64.StdEncoding.DecodeString(rec.Header().Get(hdrRequired))
	if !strings.Contains(string(raw), `"amount":"1000"`) || !strings.Contains(string(raw), wallet) {
		t.Errorf("requirements: %s", raw)
	}
	// wrong amount: the client cannot pick the price
	if rec := call(s, cfg, paymentHeader(t, s, "n0", "1"), nil); rec.Code != 402 {
		t.Errorf("a cheaper payment got %d", rec.Code)
	}
	if f.verifies != 0 {
		t.Errorf("a mismatched payment reached the facilitator")
	}
	// good payment: served, settled, response header + access token
	rec = call(s, cfg, paymentHeader(t, s, "n1", "1000"), nil)
	if rec.Code != 200 || rec.Body.String() != "paid content" || rec.Header().Get(hdrResponse) == "" || rec.Header().Get(TokenHeader) == "" {
		t.Fatalf("paid request: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	tok := rec.Header().Get(TokenHeader)
	// the same payment again: replay refused before the facilitator
	v := f.verifies
	if rec := call(s, cfg, paymentHeader(t, s, "n1", "1000"), nil); rec.Code != 402 || f.verifies != v {
		t.Errorf("replay: %d, verifies %d -> %d", rec.Code, v, f.verifies)
	}
	// token: no payment needed, no facilitator call
	rec = call(s, cfg, "", func(r *http.Request) { r.Header.Set(TokenHeader, tok) })
	if rec.Code != 200 || f.verifies != v {
		t.Errorf("token request: %d", rec.Code)
	}
	if rec := call(s, cfg, "", func(r *http.Request) { r.Header.Set(TokenHeader, tok+"x") }); rec.Code != 402 {
		t.Errorf("a tampered token got %d", rec.Code)
	}
	// a path outside the route is free
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://x.test/free", nil)
	if _, handled := s.X402(rec, req, cfg, "1.2.3.4", netip.Addr{}, false); handled {
		t.Error("an unpaid path was charged")
	}
}

func TestX402FailsClosed(t *testing.T) {
	f := &fac{verifyValid: true, settleOK: false}
	s, cfg := setup(t, f)
	var alerted atomic.Int32
	s.OnAlert = func(Event) { alerted.Add(1) }
	// settlement fails: the content is not delivered
	rec := call(s, cfg, paymentHeader(t, s, "a", "1000"), nil)
	if rec.Code != 402 || strings.Contains(rec.Body.String(), "paid content") || alerted.Load() != 1 {
		t.Errorf("settlement failure: %d %q alerts=%d", rec.Code, rec.Body.String(), alerted.Load())
	}
	// invalid signature
	f.verifyValid = false
	if rec := call(s, cfg, paymentHeader(t, s, "b", "1000"), nil); rec.Code != 402 {
		t.Errorf("invalid payment: %d", rec.Code)
	}
	// facilitator down: 503, never served
	f.down = true
	rec = call(s, cfg, paymentHeader(t, s, "c", "1000"), nil)
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "paid content") {
		t.Errorf("facilitator down: %d", rec.Code)
	}
	// nothing configured: 503 as well
	s.SetX402(X402Config{})
	if rec := call(s, cfg, "", nil); rec.Code != 503 {
		t.Errorf("unconfigured: %d", rec.Code)
	}
}

func TestX402NonceClaimRace(t *testing.T) {
	f := &fac{verifyValid: true, settleOK: true}
	s, cfg := setup(t, f)
	hdr := paymentHeader(t, s, "race", "1000")
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if call(s, cfg, hdr, nil).Code == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || f.settles != 1 {
		t.Errorf("one payment served %d requests and settled %d times", ok.Load(), f.settles)
	}
}

func TestX402BotsModeOnlyChargesBots(t *testing.T) {
	f := &fac{verifyValid: true, settleOK: true}
	s, cfg := setup(t, f)
	cfg.Routes[0].Mode = "bots"
	if rec := call(s, cfg, "", func(r *http.Request) { r.Header.Set("User-Agent", "Mozilla/5.0") }); rec.Code != 200 {
		t.Errorf("a browser was charged: %d", rec.Code)
	}
	if rec := call(s, cfg, "", func(r *http.Request) { r.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GPTBot/1.1)") }); rec.Code != 402 {
		t.Errorf("a listed bot got %d", rec.Code)
	}
	cfg.HasChallenge = true // no pass cookie on a challenged site is a bot signal
	if rec := call(s, cfg, "", func(r *http.Request) { r.Header.Set("User-Agent", "Mozilla/5.0") }); rec.Code != 402 {
		t.Errorf("a client with no pass got %d", rec.Code)
	}
}

func FuzzDecodePayment(f *testing.F) {
	f.Add("")
	f.Add(base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepted":{"scheme":"exact"},"payload":{}}`)))
	f.Add("!!!notbase64")
	f.Fuzz(func(t *testing.T, in string) { _, _ = DecodePayment(in) }) // must never panic
}
