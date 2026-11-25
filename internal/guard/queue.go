package guard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Queue cookies and endpoints.
const (
	QueueCookie = "sg_q"
	AdmitCookie = "sg_adm"
	QueueStatus = "/__servanago/queue/status"
	queueStale  = 15 * 60 // a waiting visitor that has not polled for this long is dropped
	freshAdmit  = 30      // an admit cookie younger than this passes without touching the room
)

// QueueCfg is a site's provision-time access-queue setting.
type QueueCfg struct {
	Slug      string
	Capacity  int
	ActiveTTL int // seconds
	MaxQueue  int
	Allow     []netip.Prefix
}

// room is one site's waiting room. One mutex; the queue is bounded by MaxQueue.
type room struct {
	mu       sync.Mutex
	active   map[string]int64 // sid -> last seen
	queue    []string
	seen     map[string]int64 // queued sid -> last poll
	released int64            // everyone is admitted until this unix time
	cfg      QueueCfg
}

func newRoom() *room { return &room{active: map[string]int64{}, seen: map[string]int64{}} }

func (rm *room) pos(sid string) int {
	for i, q := range rm.queue {
		if q == sid {
			return i + 1
		}
	}
	return 0
}

// admit promotes from the head while there is capacity and expires old entries (called every second).
func (rm *room) admit(now time.Time) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.cfg.Capacity == 0 {
		return
	}
	t := now.Unix()
	for sid, seen := range rm.active {
		if t-seen > int64(rm.cfg.ActiveTTL) {
			delete(rm.active, sid)
		}
	}
	keep := rm.queue[:0]
	for _, sid := range rm.queue {
		if t-rm.seen[sid] > queueStale {
			delete(rm.seen, sid)
			continue
		}
		keep = append(keep, sid)
	}
	rm.queue = keep
	for len(rm.queue) > 0 && len(rm.active) < rm.cfg.Capacity {
		sid := rm.queue[0]
		rm.queue = rm.queue[1:]
		delete(rm.seen, sid)
		rm.active[sid] = t
	}
}

type verdict int

const (
	vAdmit verdict = iota
	vWait
	vBusy
)

// enter registers a visitor with a queue cookie and returns where they stand.
func (rm *room) enter(sid string, now int64) (verdict, int, int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if _, ok := rm.active[sid]; ok {
		rm.active[sid] = now
		return vAdmit, 0, 0
	}
	if rm.pos(sid) > 0 {
		rm.seen[sid] = now
		return vWait, rm.pos(sid), len(rm.queue)
	}
	if len(rm.queue) == 0 && len(rm.active) < rm.cfg.Capacity {
		rm.active[sid] = now
		return vAdmit, 0, 0
	}
	if len(rm.queue) >= rm.cfg.MaxQueue {
		return vBusy, 0, len(rm.queue)
	}
	rm.queue = append(rm.queue, sid)
	rm.seen[sid] = now
	return vWait, len(rm.queue), len(rm.queue)
}

// QueueStats reports a site's room.
type QueueStats struct {
	Active, Waiting int
	ReleasedUntil   int64
}

func (s *Service) QueueStats(slug string) QueueStats {
	rm := s.site(slug).room
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return QueueStats{Active: len(rm.active), Waiting: len(rm.queue), ReleasedUntil: rm.released}
}

// ReleaseQueue admits everyone to the site for d (emergency release).
func (s *Service) ReleaseQueue(slug string, d time.Duration) {
	rm := s.site(slug).room
	rm.mu.Lock()
	rm.released = s.now().Add(d).Unix()
	rm.mu.Unlock()
}

func (s *Service) setCookie(w http.ResponseWriter, r *http.Request, name, val string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
}

func (s *Service) sidOf(r *http.Request) string {
	c, err := r.Cookie(QueueCookie)
	if err != nil {
		return ""
	}
	sid, mac, ok := strings.Cut(c.Value, ".")
	if !ok || !macEqual(s.mac("queue-sid", sid), mac) {
		return ""
	}
	return sid
}

// admitOf returns the sid and issue time of a valid admit cookie.
func (s *Service) admitOf(r *http.Request) (string, int64, bool) {
	c, err := r.Cookie(AdmitCookie)
	if err != nil {
		return "", 0, false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 || !macEqual(s.mac("queue-adm", parts[0], parts[1]), parts[2]) {
		return "", 0, false
	}
	iat, err := strconv.ParseInt(parts[1], 10, 64)
	return parts[0], iat, err == nil
}

func (s *Service) grantAdmit(w http.ResponseWriter, r *http.Request, sid string, ttl int) {
	iat := strconv.FormatInt(s.now().Unix(), 10)
	s.setCookie(w, r, AdmitCookie, sid+"."+iat+"."+s.mac("queue-adm", sid, iat), ttl)
}

// Queue handles one request for a queued site; true = answered.
func (s *Service) Queue(w http.ResponseWriter, r *http.Request, cfg QueueCfg, addr netip.Addr, public bool) bool {
	rm := s.site(cfg.Slug).room
	rm.mu.Lock()
	rm.cfg = cfg
	released := rm.released > s.now().Unix()
	rm.mu.Unlock()
	if r.URL.Path == QueueStatus {
		s.queueStatus(w, r, cfg, rm)
		SetOutcome(r, OutQueued)
		return true
	}
	if strings.HasPrefix(r.URL.Path, PanelPrefix) || strings.HasPrefix(r.URL.Path, "/.well-known/") || released || (public && inPrefixes(cfg.Allow, addr)) {
		return false
	}
	now := s.now().Unix()
	if sid, iat, ok := s.admitOf(r); ok && now-iat <= int64(cfg.ActiveTTL) {
		if now-iat > freshAdmit { // heartbeat: stay admitted without a capacity check, so a restart never ejects a visitor
			rm.mu.Lock()
			if len(rm.active) < 50000 {
				rm.active[sid] = now
			}
			rm.mu.Unlock()
			s.grantAdmit(w, r, sid, cfg.ActiveTTL)
		}
		return false
	}
	SetOutcome(r, OutQueued)
	sid := s.sidOf(r)
	if sid == "" { // first visit: no server state until the cookie comes back, so a cookie-less flood fills nothing
		sid = randHex(12)
		s.setCookie(w, r, QueueCookie, sid+"."+s.mac("queue-sid", sid), 24*3600)
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
			return true
		}
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Busy. Retry in a second.", http.StatusServiceUnavailable)
		return true
	}
	switch v, pos, total := rm.enter(sid, now); v {
	case vAdmit:
		s.grantAdmit(w, r, sid, cfg.ActiveTTL)
		SetOutcome(r, OutPass)
		return false
	case vBusy:
		s.alert("queue", cfg.Slug, fmt.Sprintf("The waiting room is full (%d waiting)", total))
		w.Header().Set("Retry-After", "30")
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "This site is very busy. Please try again in a few minutes.", http.StatusServiceUnavailable)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, waitPage, pos, total, QueueStatus)
	}
	return true
}

func (s *Service) queueStatus(w http.ResponseWriter, r *http.Request, cfg QueueCfg, rm *room) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	sid := s.sidOf(r)
	out := map[string]any{"admitted": false, "position": 0, "waiting": 0}
	if sid != "" {
		now := s.now().Unix()
		rm.mu.Lock()
		_, adm := rm.active[sid]
		if adm {
			rm.active[sid] = now
		} else if p := rm.pos(sid); p > 0 {
			rm.seen[sid] = now
			out["position"] = p
		}
		out["waiting"] = len(rm.queue)
		rm.mu.Unlock()
		if adm {
			s.grantAdmit(w, r, sid, cfg.ActiveTTL)
			out["admitted"] = true
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

const waitPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Please wait</title><style>body{font:16px system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f7f8;color:#1b1f23}main{max-width:30rem;padding:2rem}@media(prefers-color-scheme:dark){body{background:#14171a;color:#e7e9ea}}</style></head>
<body><main><h1>You are in line</h1><p>This site is busy. Your place: <strong id="p">%d</strong> of <span id="t">%d</span>. This page reloads when it is your turn.</p></main>
<script>setInterval(function(){fetch("%s",{credentials:"same-origin"}).then(function(r){return r.json()}).then(function(j){if(j.admitted){location.reload()}else{document.getElementById("p").textContent=j.position;document.getElementById("t").textContent=j.waiting}}).catch(function(){})},3000)</script></body></html>`
