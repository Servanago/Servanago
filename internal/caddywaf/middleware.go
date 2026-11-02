// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Owned Coraza handler: the http.handlers.waf module as Servanago builds it, adapted from
// corazawaf/coraza-caddy (Apache-2.0; see NOTICE). Differences: no Caddyfile unmarshal
// (Servanago renders JSON), no tx-id header field, and violations log through slog with the
// CRS severity mapped to a level — the hook Stage 2 feeds WAF events from.
package caddywaf

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	coreruleset "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
	"go.uber.org/zap"
)

// wafPool shares compiled WAF engines between module instances with identical configs
// (every re-rendered site, every reload): one engine per distinct tail instead of one per site.
var wafPool = caddy.NewUsagePool()

func init() {
	caddy.RegisterModule(new(Middleware))
}

type pooledWAF struct {
	waf coraza.WAF
}

func (p *pooledWAF) Destruct() error {
	var err error
	if c, ok := p.waf.(io.Closer); ok {
		if cerr := c.Close(); cerr != nil {
			err = fmt.Errorf("closing WAF: %w", cerr)
		}
	}
	p.waf = nil
	return err
}

// Middleware is the Coraza WAF handler. JSON shape (what the renderer writes):
//
//	{"handler":"waf","load_owasp_crs":true,"directives":"...","site_id":2,"rate_limit":{...}}
type Middleware struct {
	Deprecated   []string   `json:"include,omitempty"`
	Directives   string     `json:"directives"`
	LoadOWASPCRS bool       `json:"load_owasp_crs"`
	Rate         *RateLimit `json:"rate_limit,omitempty"`
	SiteID       int64      `json:"site_id,omitempty"` // names the site for WAF events; 0 = none

	logger  *zap.Logger
	waf     coraza.WAF
	limiter *rateLimiter
	poolKey string
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.waf", New: func() caddy.Module { return new(Middleware) }}
}

// Events is the hook the panel installs for violation capture: every engine callback
// (matched rule) reaches it. Nil = log only. Stage 2 wires the writer in.
// Set before the first caddy.Load that provisions a WAF handler; read-only to Caddy.
var Events func(types.MatchedRule)

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.poolKey = m.configKey()
	val, loaded, err := wafPool.LoadOrNew(m.poolKey, func() (caddy.Destructor, error) {
		waf, err := m.buildWAF()
		if err != nil {
			return nil, err
		}
		return &pooledWAF{waf: waf}, nil
	})
	if err != nil {
		return err
	}
	m.waf = val.(*pooledWAF).waf
	if loaded {
		m.logger.Info("reusing existing WAF instance from pool")
	}
	if m.Rate != nil && m.Rate.Requests > 0 && m.Rate.WindowMS > 0 {
		m.limiter = newRateLimiter(*m.Rate)
	}
	return nil
}

func (m *Middleware) buildWAF() (coraza.WAF, error) {
	config := coraza.NewWAFConfig().WithErrorCallback(severityLog)
	if m.LoadOWASPCRS {
		config = config.WithRootFS(mergefs.Merge(coreruleset.FS, corazaconf.FS, mergefsio.OSFS))
	}
	if m.Directives != "" {
		config = config.WithDirectives(m.Directives)
	}
	for _, file := range m.Deprecated {
		if s := strings.TrimSpace(file); s != "" {
			config = config.WithDirectivesFromFile(s)
		}
	}
	return coraza.NewWAF(config)
}

// configKey is the pool key: the hash of everything the engine build reads.
func (m *Middleware) configKey() string {
	h := sha256.New()
	h.Write([]byte(m.Directives))
	h.Write([]byte{0})
	sorted := make([]string, len(m.Deprecated))
	copy(sorted, m.Deprecated)
	sort.Strings(sorted)
	for _, inc := range sorted {
		h.Write([]byte(inc))
		h.Write([]byte{0})
	}
	if m.LoadOWASPCRS {
		h.Write([]byte("crs"))
	}
	return fmt.Sprintf("coraza-waf-%x", h.Sum(nil))
}

// Validate implements caddy.Validator (nothing to add beyond Provision's errors).
func (*Middleware) Validate() error { return nil }

// Cleanup releases this module instance's reference; the pool destructs the engine
// when the last instance with the same config releases.
func (m *Middleware) Cleanup() error {
	_, err := wafPool.Delete(m.poolKey)
	return err
}

// severityLog maps the CRS rule severity of a callback to a slog level, so violations
// land in journald the way the rest of the panel logs. MatchedRule carries everything
// Stage 2's event writer needs.
func severityLog(mr types.MatchedRule) {
	if ev, ok := eventOf(mr, time.Now()); ok {
		deliverEvent(ev) // dropped when the writer is off (log-only run) or the buffer is full
	}
	msg := mr.Message()
	if mr.Rule() == nil {
		slog.Warn("waf rule match", "msg", msg) // no rule metadata (a SecAction or an engine-level callback)
		return
	}
	switch mr.Rule().Severity() {
	case types.RuleSeverityEmergency, types.RuleSeverityAlert, types.RuleSeverityCritical, types.RuleSeverityError:
		slog.Error("waf rule match", "rule_id", mr.Rule().ID(), "msg", msg)
	case types.RuleSeverityWarning:
		slog.Warn("waf rule match", "rule_id", mr.Rule().ID(), "msg", msg)
	default:
		slog.Info("waf rule match", "rule_id", mr.Rule().ID(), "msg", msg)
	}
}

// interruptionError names the WAF block for Caddy's error routes ({http.error.message}).
func interruptionError(it *types.Interruption) error {
	return fmt.Errorf("interruption triggered by rule %d (%s)", it.RuleID, it.Action)
}

var _ caddy.Provisioner = (*Middleware)(nil)
var _ caddy.Validator = (*Middleware)(nil)
var _ caddy.CleanerUpper = (*Middleware)(nil)
