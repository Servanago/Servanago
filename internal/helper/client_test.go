package helper

import (
	"context"
	"net"
	"testing"
	"time"
)

// ClientRoundTrip uses the real dial path against the test socket from server_test.go.
func TestClientRoundTrip(t *testing.T) {
	ln, err := net.Listen("unix", t.TempDir()+"/helper.sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go Serve(ln, func(Peer) bool { return true }, map[string]Action{
		ActionPing: func(Request) Response { return Response{OK: true} },
	})
	c := NewClient(ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Call(ctx, ActionPing, Spec{})
	if err != nil || !resp.OK {
		t.Fatalf("ping via client: %+v %v", resp, err)
	}
	if _, err := c.Call(ctx, ActionUnitInstall, Spec{Slug: "../x"}); err == nil {
		t.Error("invalid slug accepted by server dispatch")
	}
}
