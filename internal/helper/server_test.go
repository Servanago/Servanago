package helper

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeerAllowed(t *testing.T) {
	auth := NewAuthorizer(1000)
	if !auth(Peer{UID: 0}) {
		t.Error("root must be allowed")
	}
	if !auth(Peer{UID: 1000, GID: 1000}) {
		t.Error("the servanago uid must be allowed")
	}
	for _, p := range []Peer{{UID: 999}, {UID: 1001}} {
		if auth(p) {
			t.Errorf("uid %d must not be allowed", p.UID)
		}
	}
}

// serveOn starts the server on an unix socket in a temp dir; the dialer connects to it.
func serveOn(t *testing.T, auth func(Peer) bool) string {
	t.Helper()
	ln, err := net.Listen("unix", t.TempDir()+"/helper.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go Serve(ln, auth, map[string]Action{ActionPing: func(Request) Response { return Response{OK: true} }})
	return ln.Addr().String()
}

// mustCall sends one request and reads the reply; the current process's uid passes any real
// SO_PEERCRED check, so the round trip also proves the credential plumbing works if allowed.
func mustCall(t *testing.T, socket, send string) Response {
	t.Helper()
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The server may close first (refusals, oversize input), so a write error is not fatal:
	// the reply can already be in our receive buffer.
	_, err = c.Write([]byte(send + "\n"))
	_ = err
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply for %q: %v", send, err)
	}
	var resp Response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("reply %q is not JSON: %v", line, err)
	}
	return resp
}

func TestServeRoundTrip(t *testing.T) {
	socket := serveOn(t, func(Peer) bool { return true })
	resp := mustCall(t, socket, `{"action":"ping","spec":{}}`)
	if !resp.OK || resp.Error != "" {
		t.Errorf("ping: %+v", resp)
	}
}

func TestServeRefusals(t *testing.T) {
	socket := serveOn(t, func(Peer) bool { return false })
	resp := mustCall(t, socket, `{"action":"ping","spec":{}}`)
	if resp.OK || !strings.Contains(resp.Error, "not authorized") {
		t.Errorf("unauthorized peer: %+v", resp)
	}

	socket = serveOn(t, func(Peer) bool { return true })
	resp = mustCall(t, socket, "{not json")
	if resp.OK {
		t.Errorf("bad JSON: %+v", resp)
	}
	resp = mustCall(t, socket, strings.Repeat("a", (MaxRequestSize+8)<<10))
	if resp.OK || !strings.Contains(resp.Error, "limit") {
		t.Errorf("overlong line: %+v", resp)
	}
}

// A peer that connects and sends nothing must not hold a goroutine forever.
func TestServeDropsIdlePeer(t *testing.T) {
	old := requestTimeout
	requestTimeout = 100 * time.Millisecond
	t.Cleanup(func() { requestTimeout = old })
	socket := serveOn(t, func(Peer) bool { return true })
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("the server should answer, then close, an idle peer: %v", err)
	}
	if !strings.Contains(line, "read request") {
		t.Errorf("reply %q", line)
	}
}

// Two requests for one slug never run at once (a double-clicked save); other slugs are not held up.
func TestServeSerialisesPerSlug(t *testing.T) {
	var running, peak atomic.Int32
	act := func(Request) Response {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		running.Add(-1)
		return Response{OK: true}
	}
	ln, err := net.Listen("unix", t.TempDir()+"/helper.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go Serve(ln, func(Peer) bool { return true }, map[string]Action{ActionUnitStart: act})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mustCall(t, ln.Addr().String(), `{"action":"unit-start","spec":{"slug":"app11"}}`)
		}()
	}
	wg.Wait()
	if peak.Load() != 1 {
		t.Errorf("%d unit-start calls for one slug ran at once", peak.Load())
	}
}
