package caddywaf

import (
	"strconv"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

// WafEvent is one matched rule of one request, on its way from the engine callback to
// the panel's WAF-events table (waf_events), for the site the handler rendered.
type WafEvent struct {
	SiteID  int64
	TS      int64
	RuleID  string
	Message string
	Phase   int
	Verdict string // "deny" when the match was disruptive, else "detect"
	Host    string
	Path    string
	Client  string
	Method  string
	Tags    []string
}

// pendingEvents carries the per-request skeleton (site, host, client...) by transaction
// id, so the engine callback — which sees only MatchedRule — can join it into a full
// event. ServeHTTP stores and clears it around the request; a callback without a match is
// an engine-internal one and logs only.
var pendingEvents sync.Map

// eventChan buffers between the request goroutines and the one writer goroutine; a full
// channel drops the event (tuning data, never allowed to stall a request).
var (
	eventChanOnce sync.Once
	eventChan     chan WafEvent
)

// StartEventWriter launches the single drain goroutine that hands each event to sink.
// Call it once at startup; later calls are no-ops.
func StartEventWriter(sink func(WafEvent)) {
	eventChanOnce.Do(func() {
		eventChan = make(chan WafEvent, 4096)
		go func() {
			for ev := range eventChan {
				sink(ev)
			}
		}()
	})
}

// deliverEvent queues one event; drop-on-full keeps the hot path free.
func deliverEvent(ev WafEvent) {
	if eventChan == nil {
		return // EventWriter not started: log-only
	}
	select {
	case eventChan <- ev:
	default:
	}
}

// eventOf joins the pending request skeleton with the rule match; ok=false for the
// engine-internal callbacks that carry no transaction of ours.
func eventOf(mr types.MatchedRule, now time.Time) (WafEvent, bool) {
	base, ok := pendingEvents.Load(mr.TransactionID())
	if !ok || mr.Rule() == nil {
		return WafEvent{}, false
	}
	ev := base.(WafEvent)
	ev.TS = now.Unix()
	ev.RuleID = strconv.Itoa(mr.Rule().ID())
	ev.Message = mr.Message()
	ev.Phase = int(mr.Rule().Phase())
	ev.Verdict = "detect"
	if mr.Disruptive() {
		ev.Verdict = "deny"
	}
	ev.Tags = mr.Rule().Tags()
	if len(ev.Path) > 500 {
		ev.Path = ev.Path[:500]
	}
	if len(ev.Message) > 300 {
		ev.Message = ev.Message[:300]
	}
	return ev, true
}
