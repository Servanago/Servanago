// Package alerts delivers one-line notices to ntfy, a signed webhook, email, Pushover or Twilio SMS. Send is a pure function
// (no queue, no dedupe) so the out-of-process backup and scan jobs use it as well; Notifier adds the dedupe and the bounded queue
// the web process needs. One attempt, five seconds, no retries: a failure is reported to the caller and shown on /alerts.
package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/servanago/servanago/internal/smtpx"
)

// Kinds of destination and of event.
var (
	Kinds  = []string{"ntfy", "webhook", "email", "pushover", "twilio"}
	Events = []string{"underattack", "ban", "queue", "backend", "x402", "scan", "backup"}
)

// Event is one notice. Site is the slug it concerns, "" for none.
type Event struct {
	Kind  string
	Site  string
	Key   string // extra dedupe key: a recovery must not be swallowed by the cooldown of the failure
	Title string
	Text  string
}

// Dest is a destination with its sealed values already opened.
type Dest struct {
	ID     int64
	Name   string
	Kind   string
	Target string // ntfy topic URL, webhook URL, email address, Pushover user key, Twilio "from,to"
	Secret string // ntfy token, webhook HMAC key, Pushover app token, Twilio "sid:authtoken"
}

// Sender delivers over HTTP and SMTP. The zero value works against the real services.
type Sender struct {
	// Mail returns the dialer and the From address for the email kind; nil or an unconfigured dialer = email unavailable.
	Mail func() (smtpx.Dialer, string)
	// Test seams: base URLs of the fixed services, and permission to reach loopback/http (httptest servers).
	PushoverURL, TwilioBase string
	AllowLocal              bool
	Now                     func() time.Time

	once   sync.Once
	client *http.Client
}

func (s *Sender) http() *http.Client {
	s.once.Do(func() {
		d := &net.Dialer{Timeout: 5 * time.Second}
		s.client = &http.Client{Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					if !s.AllowLocal && refused(ip) {
						continue
					}
					return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				}
				return nil, fmt.Errorf("%s resolves only to addresses that are not allowed (loopback, private or link-local)", host)
			}}}
	})
	return s.client
}

// refused: loopback, private, link-local, unspecified, multicast and CGNAT are never alert targets.
func refused(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip.Is4() {
		a := ip.As4()
		return a[0] == 100 && a[1] >= 64 && a[1] < 128
	}
	return false
}

var errScheme = errors.New("the address must be an https:// URL")

func (s *Sender) checkURL(raw string) error {
	if raw == "" || len(raw) > 500 || strings.ContainsAny(raw, " \r\n\t") {
		return errors.New("the address is empty or malformed")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("the address is not a valid URL")
	}
	if u.Scheme != "https" && !(s.AllowLocal && u.Scheme == "http") {
		return errScheme
	}
	return nil
}

// ValidateTarget checks a destination's target and secret at save time (the same rules Send applies).
func ValidateTarget(kind, target, secret string) error {
	s := &Sender{}
	switch kind {
	case "ntfy", "webhook":
		if err := s.checkURL(target); err != nil {
			return err
		}
		if kind == "webhook" && secret == "" {
			return errors.New("a webhook needs a signing secret")
		}
	case "email":
		if !strings.Contains(target, "@") || len(target) > 200 || strings.ContainsAny(target, " \r\n,;<>") {
			return errors.New("enter one email address")
		}
	case "pushover":
		if target == "" || secret == "" || len(target) > 64 || len(secret) > 64 {
			return errors.New("Pushover needs the user key and the application token")
		}
	case "twilio":
		from, to, ok := strings.Cut(target, ",")
		sid, tok, ok2 := strings.Cut(secret, ":")
		if !ok || !ok2 || from == "" || to == "" || sid == "" || tok == "" || len(target) > 60 || len(secret) > 120 {
			return errors.New(`Twilio needs the numbers as "from,to" and the credentials as "SID:auth token"`)
		}
	default:
		return errors.New("unknown destination kind")
	}
	return nil
}

func (s *Sender) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func urgent(ev Event) bool { return ev.Kind == "underattack" || ev.Kind == "scan" || ev.Kind == "x402" }

// Send delivers the event once. The error text never carries the target or the secret.
func (s *Sender) Send(ctx context.Context, d Dest, ev Event) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	title := ev.Title
	if title == "" {
		title = "ServanaGo: " + ev.Kind
	}
	text := ev.Text
	if ev.Site != "" {
		text = ev.Site + ": " + text
	}
	switch d.Kind {
	case "ntfy":
		if err := s.checkURL(d.Target); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Target, strings.NewReader(text))
		if err != nil {
			return errors.New("the ntfy address is not a valid URL")
		}
		req.Header.Set("Title", title)
		req.Header.Set("Priority", map[bool]string{true: "urgent", false: "default"}[urgent(ev)])
		req.Header.Set("Tags", "warning")
		if d.Secret != "" {
			req.Header.Set("Authorization", "Bearer "+d.Secret)
		}
		return s.do(req)
	case "webhook":
		if err := s.checkURL(d.Target); err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]any{"event": ev.Kind, "site": ev.Site, "title": title, "text": ev.Text, "time": s.now().UTC().Format(time.RFC3339)})
		ts := strconv.FormatInt(s.now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(d.Secret))
		mac.Write([]byte(ts + "." + string(body)))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Target, strings.NewReader(string(body)))
		if err != nil {
			return errors.New("the webhook address is not a valid URL")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ServanaGo-Timestamp", ts)
		req.Header.Set("X-ServanaGo-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		return s.do(req)
	case "email":
		if s.Mail == nil {
			return errors.New("email delivery is not set up on the Settings page")
		}
		dial, from := s.Mail()
		if !dial.Configured() || from == "" {
			return errors.New("email delivery is not set up on the Settings page")
		}
		return dial.Send(from, d.Target, title, text+"\n")
	case "pushover":
		base := s.PushoverURL
		if base == "" {
			base = "https://api.pushover.net/1/messages.json"
		}
		prio := "0"
		if ev.Kind == "underattack" || ev.Kind == "x402" {
			prio = "1"
		}
		form := url.Values{"token": {d.Secret}, "user": {d.Target}, "title": {title}, "message": {text}, "priority": {prio}}
		return s.post(ctx, base, form, "", "")
	case "twilio":
		from, to, _ := strings.Cut(d.Target, ",")
		sid, tok, _ := strings.Cut(d.Secret, ":")
		base := s.TwilioBase
		if base == "" {
			base = "https://api.twilio.com"
		}
		msg := title + ": " + text
		if len(msg) > 320 {
			msg = msg[:320]
		}
		form := url.Values{"From": {from}, "To": {to}, "Body": {msg}}
		return s.post(ctx, base+"/2010-04-01/Accounts/"+url.PathEscape(sid)+"/Messages.json", form, sid, tok)
	}
	return errors.New("unknown destination kind")
}

func (s *Sender) post(ctx context.Context, u string, form url.Values, user, pass string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	return s.do(req)
}

func (s *Sender) do(req *http.Request) error {
	res, err := s.http().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL carries the topic or the webhook path: keep it out of the message
		}
		return fmt.Errorf("delivery failed: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("the service answered %d", res.StatusCode)
	}
	return nil
}

// Notifier is the in-process side: dedupe by kind and site for five minutes, one goroutine draining a bounded queue.
type Notifier struct {
	Sender *Sender
	// Resolve returns the destinations that should hear the event (opened, routed per destination events and the site override).
	Resolve func(ctx context.Context, ev Event) ([]Dest, error)
	// Result is told the outcome of every delivery (err nil = delivered).
	Result func(d Dest, err error)
	Now    func() time.Time

	mu    sync.Mutex
	last  map[string]time.Time
	queue chan Event
}

const cooldown = 5 * time.Minute

// NewNotifier builds the notifier; Run drains it.
func NewNotifier(s *Sender) *Notifier {
	return &Notifier{Sender: s, Now: time.Now, last: map[string]time.Time{}, queue: make(chan Event, 256)}
}

// Notify queues the event unless the same kind and site fired within the cooldown or the queue is full. It never blocks.
func (n *Notifier) Notify(ev Event) {
	key := ev.Kind + "|" + ev.Site + "|" + ev.Key
	now := n.Now()
	n.mu.Lock()
	if t, ok := n.last[key]; ok && now.Sub(t) < cooldown {
		n.mu.Unlock()
		return
	}
	n.last[key] = now
	n.mu.Unlock()
	select {
	case n.queue <- ev:
	default:
		slog.Warn("alert queue full, event dropped", "kind", ev.Kind)
	}
}

// Run delivers queued events until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-n.queue:
			n.deliver(ctx, ev)
		}
	}
}

func (n *Notifier) deliver(ctx context.Context, ev Event) {
	dests, err := n.Resolve(ctx, ev)
	if err != nil {
		slog.Warn("alert destinations unavailable", "error", err)
		return
	}
	for _, d := range dests {
		err := n.Sender.Send(ctx, d, ev)
		if err != nil {
			slog.Warn("alert delivery failed", "destination", d.Name, "kind", d.Kind, "error", err)
		}
		if n.Result != nil {
			n.Result(d, err)
		}
	}
}

// Fire delivers synchronously to the destinations Resolve names (the backup and scan jobs, which exit right after).
func (n *Notifier) Fire(ctx context.Context, ev Event) {
	n.deliver(ctx, ev)
}
