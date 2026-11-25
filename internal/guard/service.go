// Package guard holds the runtime state of the protection layers: traffic counters and the request log, bans,
// the under-attack challenge, the access queue and the x402 paywall. Same shape as caddygeoip and caddygate: the
// Caddy modules (internal/caddyguard) look the Service up at request time, the rendered JSON pins only what
// SQLite said at render time, and state lives here keyed by site slug so a re-provision on every apply loses nothing.
package guard

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/trafficdb"
)

var current atomic.Pointer[Service]

// Install makes s the service the Caddy modules use; Current is nil until then and every module fails open.
func Install(s *Service) { current.Store(s) }
func Current() *Service  { return current.Load() }

// BanStore is the slice of the main store the ban engine persists through.
type BanStore interface {
	UpsertBan(ctx context.Context, b store.Ban) error
	DeleteBan(ctx context.Context, client string) error
	ListBans(ctx context.Context, since int64) ([]store.Ban, error)
	PruneBans(ctx context.Context, cutoff int64) error
}

// Event is what the layers tell the alert system.
type Event struct {
	Kind string // underattack ban queue backend x402
	Site string // slug; "" = not site specific
	Key  string // extra dedupe key
	Text string
}

// SiteCfg is what a site's observer module registers at provision time.
type SiteCfg struct {
	Slug         string
	BanOn        bool
	UnknownHost  bool // the catch-all route
	AutoRPS      int  // under-attack auto trigger; 0 = never
	AutoCooldown time.Duration
	Allow        []netip.Prefix // the site's allowlist: never banned, challenged, queued or charged
}

// Service is the registry. The zero value is not usable: call New.
type Service struct {
	Now func() time.Time

	// OnAlert and OnAudit are optional hooks the app wires; both must return quickly.
	OnAlert func(Event)
	OnAudit func(action, target string)
	// Turnstile verifies a challenge token (action "challenge", the request host); nil = Turnstile unavailable.
	Turnstile        func(ctx context.Context, token, ip, host string) error
	TurnstileSiteKey string

	master [32]byte
	keys   sync.Map // label -> []byte

	sites    sync.Map // slug -> *siteState
	settings atomic.Pointer[Settings]
	db       atomic.Pointer[trafficdb.DB]
	bans     BanStore

	logCh      chan trafficdb.Row
	logDropped atomic.Uint64

	banShards  [256]banShard
	banEntries atomic.Int64
	active     sync.Map // client key -> banInfo
	history    sync.Map // client key -> banInfo (level memory, 7 days)
	banBursts  atomic.Int64

	pruneDays atomic.Pointer[[2]int]

	x402 *x402State
}

// New builds a service. secret is SERVANAGO_SECRET_KEY; empty makes random per-process keys (passes and cookies reset on restart).
func New(secret string, bans BanStore) *Service {
	s := &Service{Now: time.Now, bans: bans, logCh: make(chan trafficdb.Row, 10000), x402: newX402State()}
	if secret != "" {
		s.master = sha256.Sum256([]byte(secret))
	} else {
		_, _ = rand.Read(s.master[:])
	}
	d := DefaultSettings()
	s.settings.Store(&d)
	for i := range s.banShards {
		s.banShards[i].m = map[string]*bucket{}
	}
	return s
}

// UseDB attaches (or detaches, with nil) traffic.db; without it nothing is logged or rolled up and the live ring still works.
func (s *Service) UseDB(d *trafficdb.DB) { s.db.Store(d) }

// key derives a purpose-bound key (HKDF over the master): the secretbox key itself is never used for cookies.
func (s *Service) key(label string) []byte {
	if k, ok := s.keys.Load(label); ok {
		return k.([]byte)
	}
	k, err := hkdf.Key(sha256.New, s.master[:], []byte("servanago-guard"), label, 32)
	if err != nil {
		panic(err)
	}
	s.keys.Store(label, k)
	return k
}

func (s *Service) mac(label string, parts ...string) string {
	h := hmac.New(sha256.New, s.key(label))
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func macEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

func (s *Service) now() time.Time { return s.Now() }

func (s *Service) alert(kind, slug, text string) {
	if s.OnAlert != nil {
		s.OnAlert(Event{Kind: kind, Site: slug, Text: text})
	}
}

func (s *Service) audit(action, target string) {
	if s.OnAudit != nil {
		s.OnAudit(action, target)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Key is the ban and queue key of an address: an IPv4 address as is, an IPv6 address as its /64.
func Key(a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// ParseClient turns an operator-typed single address or a /64 into a ban key.
func ParseClient(in string) (string, error) {
	in = strings.TrimSpace(in)
	if p, err := netip.ParsePrefix(in); err == nil {
		if p.Addr().Is6() && p.Bits() == 64 {
			return Key(p.Addr()), nil
		}
		if p.Addr().Is4() && p.Bits() == 32 {
			return p.Addr().String(), nil
		}
		return "", errBadClient
	}
	a, err := netip.ParseAddr(in)
	if err != nil {
		return "", errBadClient
	}
	return Key(a), nil
}

// AlertKeyed sends an event whose dedupe key is more than kind and site (backend up and down are different notices).
func (s *Service) AlertKeyed(kind, slug, key, text string) {
	if s.OnAlert != nil {
		s.OnAlert(Event{Kind: kind, Site: slug, Key: key, Text: text})
	}
}
