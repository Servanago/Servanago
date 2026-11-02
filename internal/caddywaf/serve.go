// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package caddywaf

import (
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
)

// ServeHTTP runs the four phases around the site's chain; blocks surface as Caddy
// errors for the site's error routes. Port of coraza-caddy's ServeHTTP minus the
// tx-id header field.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// The rate limiter leads the chain: an over-the-limit address is refused before any
	// rule evaluation, exactly like the geo rule leads.
	if m.serveRateLimit(w, r) {
		return nil
	}

	id := randomString(16)

	tx := m.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			slog.Warn("waf transaction close failed", "tx_id", tx.ID(), "error", err)
		}
	}()

	// Early return when no rule can run (engine off): the response writer is used as-is.
	if tx.IsRuleEngineOff() {
		return next.ServeHTTP(w, r)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", id)

	server := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	caddyhttp.PrepareRequest(r, repl, w, server)

	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{StatusCode: http.StatusInternalServerError, ID: tx.ID(), Err: err}
	} else if it != nil {
		logViolation(r, tx, it)
		return caddyhttp.HandlerError{
			StatusCode: obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK),
			ID:         tx.ID(),
			Err:        interruptionError(it),
		}
	}

	ww, processResponse := wrap(w, r, tx)
	err := next.ServeHTTP(ww, r)
	if err == nil {
		err = processResponse(tx, r)
	}
	// An interruption now comes from the response phases; the status went out with
	// the interceptor, so only the log entry remains.
	if it := tx.Interruption(); it != nil {
		logViolation(r, tx, it)
	}
	return err
}

func logViolation(r *http.Request, tx types.Transaction, it *types.Interruption) {
	client, _ := clientAddress(r)
	slog.Error("waf rule violation",
		"hostname", r.Host, "uri", r.RequestURI, "client_ip", client,
		"tx_id", tx.ID(), "rule_id", it.RuleID, "action", it.Action,
	)
}

// clientAddress resolves the client IP Caddy itself trusted (its client_ip var, filled
// per the site's trusted proxies); direct connections fall back to the socket peer.
func clientAddress(req *http.Request) (string, int) {
	if address, ok := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey).(string); ok && len(address) > 0 {
		ip, port, _ := net.SplitHostPort(address)
		if ip == "" {
			ip = address
		}
		n, _ := strconv.Atoi(port)
		return ip, n
	}
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx == -1 {
		return req.RemoteAddr, 0
	}
	port, _ := strconv.Atoi(req.RemoteAddr[idx+1:])
	return req.RemoteAddr[:idx], port
}

var _ caddyhttp.MiddlewareHandler = (*Middleware)(nil)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6 // 6 bits, enough for letterIdxMax characters
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

var src = rand.NewSource(0)
var srcMu sync.Mutex

// randomString is coraza-caddy's transaction-id helper, unchanged.
func randomString(n int) string {
	sb := new(strings.Builder)
	sb.Grow(n)

	srcMu.Lock()
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	srcMu.Unlock()

	return sb.String()
}
