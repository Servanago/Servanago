package guard

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/servanago/servanago/internal/store"
)

// clientRef is the client address of a request and whether it may be banned at all (public unicast, not a Cloudflare node).
type clientRef struct {
	addr netip.Addr
	ok   bool
}

// ClientRef builds the observer's client reference.
func ClientRef(a netip.Addr, ok bool) clientRef { return clientRef{a, ok} }

type bucket struct {
	start int64
	n     int
	codes map[int]int
}

type banShard struct {
	mu sync.Mutex
	m  map[string]*bucket
}

type banInfo struct {
	until int64
	level int
	slug  string
}

const maxBanEntries = 100000
const banMemory = 7 * 24 * time.Hour

func (s *Service) shardOf(k string) *banShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(k))
	return &s.banShards[h.Sum32()%256]
}

// Feed counts one response for the client; at the threshold inside the window the client is banned with escalation.
func (s *Service) Feed(addr netip.Addr, slug string, status int) {
	cfg := s.cfg()
	if !cfg.Codes[status] || inPrefixes(cfg.Exempt, addr) {
		return
	}
	key := Key(addr)
	if s.Banned(key) {
		return
	}
	now := s.now().Unix()
	sh := s.shardOf(key)
	sh.mu.Lock()
	b := sh.m[key]
	if b == nil || now-b.start >= int64(cfg.Window/time.Second) {
		if b == nil {
			if s.banEntries.Load() >= maxBanEntries { // at the cap new clients are not counted: fail open
				sh.mu.Unlock()
				return
			}
			s.banEntries.Add(1)
		}
		b = &bucket{start: now, codes: map[int]int{}}
		sh.m[key] = b
	}
	b.n++
	b.codes[status]++
	trip := b.n >= cfg.Threshold
	var reason string
	if trip {
		reason = reasonOf(b, cfg.Window)
		delete(sh.m, key)
		s.banEntries.Add(-1)
	}
	sh.mu.Unlock()
	if trip {
		s.ban(key, slug, "auto", reason, "", 0)
	}
}

func reasonOf(b *bucket, w time.Duration) string {
	var cs []int
	for c := range b.codes {
		cs = append(cs, c)
	}
	sort.Ints(cs)
	var parts []string
	for _, c := range cs {
		parts = append(parts, fmt.Sprintf("%dx%d", c, b.codes[c]))
	}
	return fmt.Sprintf("%d responses in %ds: %s", b.n, int(w/time.Second), strings.Join(parts, " "))
}

// ban installs a ban. d == 0 means "next escalation step"; a manual ban passes its duration.
func (s *Service) ban(key, slug, source, reason, by string, d time.Duration) store.Ban {
	cfg := s.cfg()
	now := s.now()
	level := 1
	if prev, ok := s.history.Load(key); ok {
		p := prev.(banInfo)
		if now.Unix() <= p.until+int64(banMemory/time.Second) {
			level = p.level + 1
		}
	}
	if level > len(cfg.Steps) {
		level = len(cfg.Steps)
	}
	if d == 0 {
		d = cfg.Steps[level-1]
	}
	info := banInfo{until: now.Add(d).Unix(), level: level, slug: slug}
	s.active.Store(key, info)
	s.history.Store(key, info)
	b := store.Ban{Client: key, SiteSlug: slug, Source: source, Level: level, Reason: reason, CreatedAt: now.Unix(), Until: info.until, CreatedBy: by}
	if s.bans != nil {
		write := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.bans.UpsertBan(ctx, b); err != nil {
				slog.Warn("ban write failed", "client", key, "error", err)
			}
		}
		if source == "manual" { // the panel lists the row right after this returns
			write()
		} else { // an automatic ban is already enforced in memory; the row follows off the request path
			go write()
		}
	}
	if source == "auto" {
		s.audit("ban.created", key)
		n := s.banBursts.Add(1)
		s.alert("ban", slug, fmt.Sprintf("%s banned for %s (level %d): %s [%d bans since the last alert]", key, d.Round(time.Minute), level, reason, n))
	}
	return b
}

// Banned is the hot-path check: one map lookup, no SQLite.
func (s *Service) Banned(key string) bool {
	v, ok := s.active.Load(key)
	if !ok {
		return false
	}
	if v.(banInfo).until <= s.now().Unix() {
		s.active.Delete(key)
		return false
	}
	return true
}

// Ban bans a client by hand for d.
func (s *Service) Ban(client, slug, by, reason string, d time.Duration) (store.Ban, error) {
	key, err := ParseClient(client)
	if err != nil {
		return store.Ban{}, err
	}
	if d <= 0 {
		return store.Ban{}, errors.New("a manual ban needs a duration")
	}
	return s.ban(key, slug, "manual", reason, by, d), nil
}

// Unban lifts a ban and forgets its escalation history.
func (s *Service) Unban(client string) error {
	key, err := ParseClient(client)
	if err != nil {
		key = client // a stored key typed back from the list
	}
	s.active.Delete(key)
	s.history.Delete(key)
	if s.bans == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.bans.DeleteBan(ctx, key)
}

// LoadBans restores the unexpired bans and the escalation memory at startup.
func (s *Service) LoadBans(ctx context.Context) error {
	if s.bans == nil {
		return nil
	}
	rows, err := s.bans.ListBans(ctx, s.now().Add(-banMemory).Unix())
	if err != nil {
		return err
	}
	now := s.now().Unix()
	for _, b := range rows {
		info := banInfo{until: b.Until, level: b.Level, slug: b.SiteSlug}
		s.history.Store(b.Client, info)
		if b.Until > now {
			s.active.Store(b.Client, info)
		}
	}
	return nil
}

// ActiveBans lists the bans in force, newest first (the panel's /bans page reads the store; this is the live view for counts).
func (s *Service) ActiveCount() int {
	n, now := 0, s.now().Unix()
	s.active.Range(func(_, v any) bool {
		if v.(banInfo).until > now {
			n++
		}
		return true
	})
	return n
}

// sweepBans drops expired counters and resets the burst counter used in alert text.
func (s *Service) sweepBans(now time.Time) {
	win := int64(s.cfg().Window / time.Second)
	for i := range s.banShards {
		sh := &s.banShards[i]
		sh.mu.Lock()
		for k, b := range sh.m {
			if now.Unix()-b.start >= win {
				delete(sh.m, k)
				s.banEntries.Add(-1)
			}
		}
		sh.mu.Unlock()
	}
	s.active.Range(func(k, v any) bool {
		if v.(banInfo).until <= now.Unix() {
			s.active.Delete(k)
		}
		return true
	})
	s.banBursts.Store(0)
}

// itoa avoids an import in sibling files.
func itoa(n int) string { return strconv.Itoa(n) }
