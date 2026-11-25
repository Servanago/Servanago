package guard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// x402 v2 over HTTP (github.com/x402-foundation/x402, specs/transports-v2/http.md): the server answers 402 with a
// base64 PaymentRequired in PAYMENT-REQUIRED; the client retries with a base64 PaymentPayload in PAYMENT-SIGNATURE;
// a facilitator verifies and settles; PAYMENT-RESPONSE carries the settlement. This is the minimal in-house client.
const (
	hdrRequired  = "PAYMENT-REQUIRED"
	hdrSignature = "PAYMENT-SIGNATURE"
	hdrResponse  = "PAYMENT-RESPONSE"
	TokenCookie  = "sg_x402"
	TokenHeader  = "X-ServanaGo-Access"
	maxPayHeader = 16 << 10
)

// Assets: USDC (6 decimals) per supported network, with the EIP-712 domain the exact scheme needs.
type asset struct {
	Address, Name, Version string
}

var assets = map[string]asset{
	"eip155:8453":  {"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USD Coin", "2"}, // Base
	"eip155:84532": {"0x036CbD53842c5426634e7929541eC2318f3dCF7e", "USDC", "2"},     // Base Sepolia
}

// Networks lists the supported network ids.
func Networks() []string { return []string{"eip155:8453", "eip155:84532"} }

// X402Config is the global wallet and facilitator setting.
type X402Config struct {
	Facilitator string
	Network     string
	PayTo       string
	APIKey      string // plaintext, in memory only
}

func (c X402Config) ready() bool {
	_, ok := assets[c.Network]
	return c.Facilitator != "" && c.PayTo != "" && ok
}

type x402State struct {
	cfg    X402Config
	mu     sync.Mutex
	claims map[string]int64 // payment nonce -> expiry
	client *http.Client
}

func newX402State() *x402State {
	return &x402State{claims: map[string]int64{}, client: &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// SetX402 installs the wallet and facilitator.
func (s *Service) SetX402(c X402Config) {
	s.x402.mu.Lock()
	s.x402.cfg = c
	s.x402.mu.Unlock()
}

func (s *Service) x402cfg() X402Config {
	s.x402.mu.Lock()
	defer s.x402.mu.Unlock()
	return s.x402.cfg
}

// X402Route is one paywalled prefix.
type X402Route struct {
	Path  string
	Price string // decimal USD
	Mode  string // all | bots
	Grant string // request | token
	TTL   int    // token seconds
}

// X402Cfg is the module's provision-time setting.
type X402Cfg struct {
	Slug         string
	Routes       []X402Route
	HasChallenge bool // the site has a challenge: "no pass cookie" counts as a bot signal
	Allow        []netip.Prefix
}

var errPrice = errors.New("price must be a positive decimal with at most 6 decimals, for example 0.001")

// PriceToUnits converts a decimal USD string to USDC base units (6 decimals) without floats.
func PriceToUnits(p string) (string, error) {
	whole, frac, _ := strings.Cut(strings.TrimSpace(p), ".")
	if whole == "" && frac == "" || len(whole)+len(frac) > 18 || len(frac) > 6 {
		return "", errPrice
	}
	for _, part := range []string{whole, frac} {
		for _, r := range part {
			if r < '0' || r > '9' {
				return "", errPrice
			}
		}
	}
	for len(frac) < 6 {
		frac += "0"
	}
	n, ok := new(big.Int).SetString(whole+frac, 10)
	if !ok || n.Sign() <= 0 {
		return "", errPrice
	}
	return n.String(), nil
}

// ValidWallet checks "0x" plus 40 hex digits (the checksum is not enforced).
func ValidWallet(w string) bool {
	if len(w) != 42 || !strings.HasPrefix(w, "0x") {
		return false
	}
	for _, r := range w[2:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// Requirements is one accepted payment option.
type Requirements struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra"`
}

type resource struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type paymentRequired struct {
	X402Version int            `json:"x402Version"`
	Error       string         `json:"error"`
	Resource    resource       `json:"resource"`
	Accepts     []Requirements `json:"accepts"`
}

// Payment is the decoded PAYMENT-SIGNATURE payload; Raw is forwarded to the facilitator untouched.
type Payment struct {
	X402Version int             `json:"x402Version"`
	Accepted    Requirements    `json:"accepted"`
	Payload     json.RawMessage `json:"payload"`
	Raw         json.RawMessage `json:"-"`
}

// DecodePayment parses the PAYMENT-SIGNATURE header. It rejects anything oversized, malformed or incomplete.
func DecodePayment(h string) (Payment, error) {
	var p Payment
	if h == "" || len(h) > maxPayHeader {
		return p, errors.New("payment header missing or too large")
	}
	raw, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(h); err != nil {
			return p, errors.New("payment header is not base64")
		}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, errors.New("payment header is not JSON")
	}
	if p.X402Version != 2 || len(p.Payload) == 0 || p.Accepted.Scheme == "" {
		return p, errors.New("payment payload incomplete")
	}
	p.Raw = raw
	return p, nil
}

// nonceOf is the unique id of the payment authorization (EIP-3009 nonce), falling back to the signature.
func nonceOf(p Payment) string {
	var body struct {
		Signature     string `json:"signature"`
		Authorization struct {
			Nonce string `json:"nonce"`
		} `json:"authorization"`
	}
	_ = json.Unmarshal(p.Payload, &body)
	switch {
	case body.Authorization.Nonce != "":
		return strings.ToLower(body.Authorization.Nonce)
	case body.Signature != "":
		return strings.ToLower(body.Signature)
	}
	return ""
}

// claim records the nonce atomically; false = already claimed (a replay or a concurrent twin).
func (st *x402State) claim(nonce string, now, ttl int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if exp, ok := st.claims[nonce]; ok && exp > now {
		return false
	}
	if len(st.claims) > 10000 {
		for k, exp := range st.claims {
			if exp <= now {
				delete(st.claims, k)
			}
		}
	}
	st.claims[nonce] = now + ttl
	return true
}

func (s *Service) requirementsFor(c X402Config, units string, r *http.Request) Requirements {
	a := assets[c.Network]
	return Requirements{Scheme: "exact", Network: c.Network, Amount: units, Asset: a.Address, PayTo: c.PayTo, MaxTimeoutSeconds: 60,
		Extra: map[string]any{"name": a.Name, "version": a.Version}}
}

func sameReq(a, b Requirements) bool {
	return a.Scheme == b.Scheme && a.Network == b.Network && a.Amount == b.Amount &&
		strings.EqualFold(a.Asset, b.Asset) && strings.EqualFold(a.PayTo, b.PayTo)
}

func matchRoute(rs []X402Route, path string) (X402Route, bool) {
	sorted := append([]X402Route(nil), rs...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Path) > len(sorted[j].Path) })
	for _, x := range sorted {
		if strings.HasPrefix(path, x.Path) {
			return x, true
		}
	}
	return X402Route{}, false
}

func (s *Service) isBot(r *http.Request, cfg X402Cfg, client string) bool {
	ua := strings.ToLower(r.UserAgent())
	for _, b := range s.cfg().UAList {
		if strings.Contains(ua, b) {
			return true
		}
	}
	if cfg.HasChallenge && !s.HasPass(r, cfg.Slug, client) {
		return true
	}
	flagged, _ := caddyhttp.GetVar(r.Context(), "sg_waf_flagged").(bool)
	return flagged
}

func (s *Service) tokenValid(r *http.Request, slug, path string) bool {
	v := r.Header.Get(TokenHeader)
	if v == "" {
		if c, err := r.Cookie(TokenCookie); err == nil {
			v = c.Value
		}
	}
	exp, mac, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && n > s.now().Unix() && macEqual(s.mac("x402-token", slug, path, exp), mac)
}

func (s *Service) tokenFor(slug, path string, ttl int) string {
	exp := strconv.FormatInt(s.now().Add(time.Duration(ttl)*time.Second).Unix(), 10)
	return exp + "." + s.mac("x402-token", slug, path, exp)
}

func (s *Service) deny402(w http.ResponseWriter, r *http.Request, c X402Config, route X402Route, units, msg string) {
	req := s.requirementsFor(c, units, r)
	pr := paymentRequired{X402Version: 2, Error: msg, Resource: resource{URL: "https://" + r.Host + r.URL.Path}, Accepts: []Requirements{req}}
	body, _ := json.Marshal(pr)
	w.Header().Set(hdrRequired, base64.StdEncoding.EncodeToString(body))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	SetOutcome(r, OutPayment)
	w.WriteHeader(http.StatusPaymentRequired)
	_, _ = w.Write(body)
}

// X402 enforces the paywall. It returns handled=true when it answered; otherwise the module must call next, using the
// returned writer (it settles the payment when the upstream declares a success status).
func (s *Service) X402(w http.ResponseWriter, r *http.Request, cfg X402Cfg, client string, addr netip.Addr, public bool) (http.ResponseWriter, bool) {
	if strings.HasPrefix(r.URL.Path, PanelPrefix) || strings.HasPrefix(r.URL.Path, "/.well-known/") || (public && inPrefixes(cfg.Allow, addr)) {
		return w, false
	}
	route, ok := matchRoute(cfg.Routes, r.URL.Path)
	if !ok || (route.Mode == "bots" && !s.isBot(r, cfg, client)) {
		return w, false
	}
	if route.Grant == "token" && s.tokenValid(r, cfg.Slug, route.Path) {
		return w, false
	}
	conf := s.x402cfg()
	if !conf.ready() { // never serve paid content unverified
		w.Header().Set("Retry-After", "60")
		SetOutcome(r, OutPayment)
		http.Error(w, "Payment is not configured on this server.", http.StatusServiceUnavailable)
		return w, true
	}
	units, err := PriceToUnits(route.Price)
	if err != nil {
		http.Error(w, "Payment misconfigured.", http.StatusServiceUnavailable)
		return w, true
	}
	hdr := r.Header.Get(hdrSignature)
	if hdr == "" {
		s.deny402(w, r, conf, route, units, "PAYMENT-SIGNATURE header is required")
		return w, true
	}
	pay, err := DecodePayment(hdr)
	req := s.requirementsFor(conf, units, r)
	if err != nil || !sameReq(pay.Accepted, req) {
		s.deny402(w, r, conf, route, units, "payment does not match the requirements")
		return w, true
	}
	nonce := nonceOf(pay)
	if nonce == "" || !s.x402.claim(nonce, s.now().Unix(), int64(req.MaxTimeoutSeconds)*10+3600) {
		s.deny402(w, r, conf, route, units, "payment already used")
		return w, true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	vr, err := s.facilitate(ctx, conf, "/verify", pay, req)
	if err != nil {
		s.alert("x402", cfg.Slug, "The x402 facilitator is not answering: "+err.Error())
		w.Header().Set("Retry-After", "5")
		SetOutcome(r, OutPayment)
		http.Error(w, "Payment service unavailable.", http.StatusServiceUnavailable)
		return w, true
	}
	if !vr.IsValid {
		s.deny402(w, r, conf, route, units, "payment rejected: "+vr.InvalidReason)
		return w, true
	}
	SetOutcome(r, OutPayment)
	return &settleWriter{ResponseWriter: w, s: s, r: r, cfg: cfg, route: route, conf: conf, pay: pay, req: req, units: units}, false
}

type facilitatorReply struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason"`
	Success       bool   `json:"success"`
	ErrorReason   string `json:"errorReason"`
	Raw           []byte `json:"-"`
}

// facilitate POSTs {paymentPayload, paymentRequirements} to the facilitator's /verify or /settle.
func (s *Service) facilitate(ctx context.Context, c X402Config, path string, pay Payment, req Requirements) (facilitatorReply, error) {
	body, _ := json.Marshal(map[string]any{"x402Version": 2, "paymentPayload": json.RawMessage(pay.Raw), "paymentRequirements": req})
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Facilitator, "/")+path, bytes.NewReader(body))
	if err != nil {
		return facilitatorReply{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		hr.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	res, err := s.x402.client.Do(hr)
	if err != nil {
		return facilitatorReply{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode >= 500 {
		return facilitatorReply{}, fmt.Errorf("facilitator answered %d", res.StatusCode)
	}
	var out facilitatorReply
	if err := json.Unmarshal(raw, &out); err != nil {
		return facilitatorReply{}, fmt.Errorf("facilitator answered %d with a body that is not JSON", res.StatusCode)
	}
	out.Raw = raw
	return out, nil
}

// settleWriter settles the verified payment at the moment the upstream declares its status: success statuses are
// settled before any byte goes out, so a settlement failure becomes a 402 instead of free content.
type settleWriter struct {
	http.ResponseWriter
	s       *Service
	r       *http.Request
	cfg     X402Cfg
	route   X402Route
	conf    X402Config
	pay     Payment
	req     Requirements
	units   string
	done    bool
	dropped bool
}

func (w *settleWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *settleWriter) WriteHeader(code int) {
	if w.done {
		return
	}
	w.done = true
	if code >= 400 || code < 200 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sr, err := w.s.facilitate(ctx, w.conf, "/settle", w.pay, w.req)
	if err != nil || !sr.Success {
		if err != nil {
			w.s.alert("x402", w.cfg.Slug, "x402 settlement failed: "+err.Error())
		} else if sr.ErrorReason != "" {
			w.s.alert("x402", w.cfg.Slug, "x402 settlement rejected: "+sr.ErrorReason)
		}
		w.dropped = true
		h := w.Header()
		for k := range h {
			delete(h, k)
		}
		w.s.deny402(w.ResponseWriter, w.r, w.conf, w.route, w.units, "settlement failed")
		return
	}
	w.Header().Set(hdrResponse, base64.StdEncoding.EncodeToString(sr.Raw))
	if w.route.Grant == "token" {
		tok := w.s.tokenFor(w.cfg.Slug, w.route.Path, w.route.TTL)
		w.Header().Set(TokenHeader, tok)
		http.SetCookie(w.ResponseWriter, &http.Cookie{Name: TokenCookie, Value: tok, Path: "/", MaxAge: w.route.TTL, HttpOnly: true, Secure: w.r.TLS != nil, SameSite: http.SameSiteLaxMode})
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *settleWriter) Write(b []byte) (int, error) {
	if !w.done {
		w.WriteHeader(http.StatusOK)
	}
	if w.dropped {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *settleWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok && !w.dropped {
		f.Flush()
	}
}
