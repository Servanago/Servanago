package apply

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caretakarr/caretakarr/internal/caddycfg"
	"github.com/caretakarr/caretakarr/internal/caddylog"
	"github.com/caretakarr/caretakarr/internal/caddytest"
	"github.com/caretakarr/caretakarr/internal/store"
)

// A real ACME issuer pointed at a dead CA must fail issuance and surface it in the log ring.
func TestACMEFailureAppearsInLogRing(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", strings.Repeat("a", 40))
	storage := t.TempDir()
	caddytest.Cleanup(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, caddycfg.Options{
		UIHost: "ui.example.com", UIUpstream: "127.0.0.1:9", Email: "me@example.com", Issuer: caddycfg.ACME,
		CA:        "http://127.0.0.1:" + strconv.Itoa(caddytest.FreePort(t)) + "/directory", // nothing listens there
		Resolvers: []string{"127.0.0.1"}, HTTPPort: caddytest.FreePort(t), HTTPSPort: caddytest.FreePort(t), StoragePath: storage,
	})
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for caddylog.Sink.LastError("ui.example.com") == "" {
		if time.Now().After(deadline) {
			t.Fatalf("no ACME error in the ring; entries: %v", caddylog.Sink.Lines())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
