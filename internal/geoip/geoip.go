// Package geoip reads MaxMind's GeoLite2-Country mmdb (geoipupdate keeps it fresh; ServanaGo only
// reads the file) and answers the one question the rules ask: is this IP's country on the list?
package geoip

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type DB struct {
	mu    sync.Mutex
	path  string
	rd    *geoip2.Reader
	mtime time.Time
	err   error // the last open failure; stable until the file changes, so callers can log once per state
}

func New() *DB { return &DB{} }

// Use points the DB at a file; an empty path turns geo off.
func (d *DB) Use(path string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.path == path {
		return
	}
	d.path = path
	d.rd, d.mtime, d.err = nil, time.Time{}, nil
}

// Lookup resolves the IP's ISO 3166-1 alpha-2 code; the empty string when the database has no
// entry (private, unknown or unrouted addresses — including the whole RFC1918/CGNAT space),
// which every rule treats as "unknown country". The reader reopens when the file changes.
func (d *DB) Lookup(ip netip.Addr) (string, error) {
	if !ip.IsValid() {
		return "", nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.path == "" {
		return "", nil
	}
	if info, serr := os.Stat(d.path); serr != nil {
		if d.err == nil {
			d.err = fmt.Errorf("no geoip database at %s", d.path)
		}
		d.rd, d.mtime = nil, time.Time{}
		return "", d.err
	} else if info.ModTime() != d.mtime || d.rd == nil {
		d.mtime = info.ModTime()
		newRd, oerr := geoip2.Open(d.path)
		if oerr != nil {
			if d.rd != nil {
				_ = d.rd.Close()
			}
			d.rd = nil
			d.err = fmt.Errorf("open %s: %w", d.path, oerr)
			return "", d.err
		}
		if d.rd != nil {
			_ = d.rd.Close()
		}
		d.rd = newRd
		d.err = nil
	}
	if d.err != nil {
		return "", d.err
	}
	rec, err := d.rd.Country(netIP(ip))
	if err != nil {
		return "", fmt.Errorf("geoip lookup %s: %w", ip, err)
	}
	return rec.Country.IsoCode, nil // RegisteredCountry would guess; keep the strict answer
}

// netIP converts a netip address the reader accepts (IPv4 stays 4-byte).
func netIP(ip netip.Addr) net.IP {
	if ip.Is4() {
		a4 := ip.As4()
		return net.IP(a4[:])
	}
	a16 := ip.As16()
	return net.IP(a16[:])
}

// Blocked is the country rule: deny = a listed (and known) country is out, anything else passes;
// allow = only the listed countries pass, unknown included. An empty mode never blocks.
func Blocked(mode, country string, want map[string]bool) bool {
	switch mode {
	case "deny":
		return country != "" && want[country]
	case "allow":
		return country == "" || !want[country]
	default:
		return false
	}
}

// Codes parses a space-separated country list into the set Blocked reads.
func Codes(countries string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.Fields(countries) {
		out[strings.ToUpper(f)] = true
	}
	return out
}
