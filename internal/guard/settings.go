package guard

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/store"
)

var errBadClient = errors.New("enter one IP address, or an IPv6 /64")

// Settings is the parsed form of store.GuardSettings the hot paths read.
type Settings struct {
	Codes       map[int]bool
	UnknownHost bool
	Threshold   int
	Window      time.Duration
	Steps       []time.Duration
	Exempt      []netip.Prefix
	UAList      []string
}

func DefaultSettings() Settings {
	return ParseSettings(store.GuardSettings{BanCodes: "401 403 429", BanThreshold: 20, BanWindowS: 60, BanStepsMin: "15 60 1440",
		UAList: "GPTBot ClaudeBot CCBot PerplexityBot Bytespider Amazonbot Google-Extended"})
}

// ParseSettings never fails: a value that does not parse falls back to the default, so a bad row cannot disable the engine.
func ParseSettings(g store.GuardSettings) Settings {
	s := Settings{UnknownHost: g.BanUnknownHost, Threshold: g.BanThreshold, Window: time.Duration(g.BanWindowS) * time.Second,
		Codes: map[int]bool{}}
	if s.Threshold < 1 {
		s.Threshold = 20
	}
	if s.Window < time.Second {
		s.Window = 60 * time.Second
	}
	for _, f := range strings.Fields(g.BanCodes) {
		if n, err := strconv.Atoi(f); err == nil && n >= 100 && n < 600 {
			s.Codes[n] = true
		}
	}
	for _, f := range strings.Fields(g.BanStepsMin) {
		if n, err := strconv.Atoi(f); err == nil && n > 0 {
			s.Steps = append(s.Steps, time.Duration(n)*time.Minute)
		}
	}
	if len(s.Steps) == 0 {
		s.Steps = []time.Duration{15 * time.Minute, time.Hour, 24 * time.Hour}
	}
	for _, f := range strings.Fields(g.BanExempt) {
		if p, err := netip.ParsePrefix(f); err == nil {
			s.Exempt = append(s.Exempt, p)
		} else if a, err := netip.ParseAddr(f); err == nil {
			s.Exempt = append(s.Exempt, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, f := range strings.Fields(g.UAList) {
		s.UAList = append(s.UAList, strings.ToLower(f))
	}
	return s
}

// SetSettings swaps the runtime settings (called at start and after the settings form saves).
func (s *Service) SetSettings(g store.GuardSettings) {
	p := ParseSettings(g)
	s.settings.Store(&p)
}

func (s *Service) cfg() *Settings { return s.settings.Load() }

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// ParseAllow reads a site's allowlist (CIDRs or addresses, whitespace separated) leniently.
func ParseAllow(list string) []netip.Prefix {
	return ParseSettings(store.GuardSettings{BanExempt: list}).Exempt
}
