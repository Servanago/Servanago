package helper

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// requestTimeout bounds how long a peer may take to send its one request line.
var requestTimeout = 10 * time.Second

// slugLocks holds one mutex per slug; the set of slugs is small, so entries are never dropped.
var slugLocks sync.Map

func slugLock(slug string) *sync.Mutex {
	mu, _ := slugLocks.LoadOrStore(slug, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// Peer is what SO_PEERCRED reports about the client process.
type Peer struct {
	UID, GID uint32
}

// NewAuthorizer allows root and the servanago user's uid. Nothing else may call the helper.
func NewAuthorizer(allowedUID uint32) func(Peer) bool {
	return func(p Peer) bool { return p.UID == 0 || p.UID == allowedUID }
}

// HelperUID resolves the servanago system user the control plane runs as; ok=false means only
// root may call (a host without the user still runs helpers for manual/root setups).
func HelperUID() (uid uint32, ok bool) {
	u, err := user.Lookup("servanago")
	if err != nil {
		return 0, false
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}

// Action performs one decoded request. It must never trust anything beyond the validated fields.
type Action func(Request) Response

// Serve accepts connections until the listener closes: per connection one credential check, one
// request, one reply, close. The helper never keeps client state.
func Serve(ln net.Listener, auth func(Peer) bool, actions map[string]Action) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Error("helper accept", "error", err)
			}
			return
		}
		go handle(c, auth, actions)
	}
}

func handle(c net.Conn, auth func(Peer) bool, actions map[string]Action) {
	defer c.Close()
	respond := func(resp Response) {
		b, err := json.Marshal(resp)
		if err == nil {
			_, _ = c.Write(append(b, '\n'))
		}
	}
	p, ok := peerCred(c)
	if !ok {
		respond(Response{Error: "could not read peer credentials"})
		return
	}
	if !auth(p) {
		slog.Error("helper refused peer", "uid", p.UID)
		respond(Response{Error: "peer not authorized"})
		return
	}
	if err := c.SetReadDeadline(time.Now().Add(requestTimeout)); err != nil { // a silent peer must not hold this goroutine
		respond(Response{Error: fmt.Sprintf("read request: %v", err)})
		return
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 4096), MaxRequestSize+8)
	if !sc.Scan() {
		if errors.Is(sc.Err(), bufio.ErrTooLong) {
			respond(Response{Error: "request exceeds the size limit"})
		} else {
			respond(Response{Error: fmt.Sprintf("read request: %v", sc.Err())})
		}
		return
	}
	req, err := DecodeRequest(sc.Bytes())
	if err != nil {
		respond(Response{Error: err.Error()})
		return
	}
	act, ok := actions[req.Action]
	if !ok {
		respond(Response{Error: "no such action " + req.Action})
		return
	}
	if slug := req.Vals.Slug; slug != "" { // one action per site at a time: a double-clicked save must not interleave file writes
		mu := slugLock(slug)
		mu.Lock()
		defer mu.Unlock()
	}
	resp := act(req)
	slog.Info("helper action", "action", req.Action, "ok", resp.OK)
	respond(resp)
}

// peerCred reads SO_PEERCRED from an unix socket; other socket kinds return false.
func peerCred(c net.Conn) (Peer, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, false
	}
	var p Peer
	var credErr error
	rc, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, false
	}
	if cerr := rc.Control(func(fd uintptr) {
		var u *syscall.Ucred
		u, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if credErr == nil {
			p = Peer{UID: u.Uid, GID: u.Gid}
		}
	}); cerr != nil {
		return Peer{}, false
	}
	if credErr != nil {
		return Peer{}, false
	}
	return p, true
}

// SocketPath is where the control plane finds the helper.
const SocketPath = "/run/servanago/helper.sock"

// Listen builds the helper's listener: mode 0660, group servanago, so the unprivileged UI may
// connect (parent dir 0750 root:servanago comes from the helper unit's RuntimeDirectory).
func Listen() (net.Listener, error) {
	ln, err := net.Listen("unix", SocketPath)
	if err != nil {
		// A restarted helper may find the stale socket of a crashed previous run.
		if d, e := net.Dial("unix", SocketPath); e == nil {
			d.Close()
			return nil, fmt.Errorf("%s is already served", SocketPath)
		}
		if rmErr := os.Remove(SocketPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale socket: %w", rmErr)
		}
		ln, err = net.Listen("unix", SocketPath)
		if err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(SocketPath, 0o660); err != nil {
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	if g, err := user.LookupGroup("servanago"); err == nil {
		if gid, gerr := strconv.Atoi(g.Gid); gerr == nil {
			if cherr := os.Chown(SocketPath, -1, gid); cherr != nil {
				return nil, fmt.Errorf("chown socket: %w", cherr)
			}
		}
	}
	return ln, nil
}
