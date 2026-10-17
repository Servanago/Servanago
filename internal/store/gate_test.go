package store

import (
	"context"
	"testing"
	"time"
)

// now is a fixed RFC3339 clock the tests pass down through every call.
var now = "2026-10-15T10:00:00Z"

func gateStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.CreateSite(context.Background(), Site{Hostnames: []string{"st.example.com"}, Scheme: "http",
		UpstreamHost: "192.168.1.20", UpstreamPort: 8989, Enabled: true, GateMode: "acl"}); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestGateModeRoundTrip(t *testing.T) {
	st := gateStore(t)
	ctx := context.Background()
	r, err := st.ListSites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r[0].GateMode != "acl" {
		t.Fatalf("gate mode lost: %q", r[0].GateMode)
	}
	r[0].GateMode = "open"
	if err := st.UpdateSite(ctx, r[0]); err != nil {
		t.Fatal(err)
	}
	if r, _ = st.ListSites(ctx); r[0].GateMode != "open" {
		t.Fatalf("update lost gate mode: %q", r[0].GateMode)
	}
}

func TestReplaceGrantsAndAutoRevoke(t *testing.T) {
	st := gateStore(t)
	ctx := context.Background()
	r, _ := st.ListSites(ctx)
	if err := st.ReplaceGrants(ctx, r[0].ID, []Grant{{Mode: "email", Value: "alice@example.com"}, {Mode: "domain", Value: "dev.example"}}); err != nil {
		t.Fatal(err)
	}
	gs, err := st.Grants(ctx, r[0].ID)
	if err != nil || len(gs) != 2 {
		t.Fatalf("grants: %v %v", gs, err)
	}
	// An identity whose only qualifying grant lives here is deleted when it is removed.
	if err := st.UpsertIdentity(ctx, "alice@example.com", "n1", "h1", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceGrants(ctx, r[0].ID, []Grant{{Mode: "email", Value: "bob@example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.Session(ctx, "h1", now); err != nil || ok {
		t.Fatalf("orphan session still valid: %v %v", ok, err)
	}
	// A surviving grant keeps the session.
	if err := st.UpsertIdentity(ctx, "alice@example.com", "n2", "h2", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	r2, _ := st.CreateSite(ctx, Site{Hostnames: []string{"st.dev.example"}, Scheme: "http", UpstreamHost: "1.2.3.4", UpstreamPort: 1, Enabled: true, GateMode: "acl"})
	if err := st.ReplaceGrants(ctx, r2.ID, []Grant{{Mode: "domain", Value: "dev.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceGrants(ctx, r[0].ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.Session(ctx, "h2", now); err != nil || !ok {
		t.Fatalf("session with surviving grant revoked: %v %v", ok, err)
	}
}

func TestSessionExpiryDeletes(t *testing.T) {
	st := gateStore(t)
	ctx := context.Background()
	if err := st.UpsertIdentity(ctx, "a@b.c", "n", "hash", now, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.Session(ctx, "hash", now); err != nil || !ok {
		t.Fatalf("fresh session: %v %v", ok, err)
	}
	if _, ok, _ := st.Session(ctx, "hash", "2026-12-01T00:00:00Z"); ok {
		t.Fatal("expired session accepted")
	}
	if _, ok, _ := st.Session(ctx, "hash", "2026-10-16T00:00:00Z"); ok {
		t.Fatal("row survived expiry deletion")
	}
}

func TestTouchSlidesWindow(t *testing.T) {
	st := gateStore(t)
	ctx := context.Background()
	if err := st.UpsertIdentity(ctx, "a@b.c", "n", "hash", now, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchSession(ctx, "hash", "2026-10-20T00:00:00Z", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.Session(ctx, "hash", "2026-10-20T23:00:00Z"); !ok {
		t.Fatal("touch did not extend")
	}
	if _, ok, _ := st.Session(ctx, "hash", "2026-10-21T00:00:01Z"); ok {
		t.Fatal("touched window not honored")
	}
}

func TestTokensSingleUse(t *testing.T) {
	st := gateStore(t)
	ctx := context.Background()
	consume := func(token, at string) (string, bool) {
		email, ok, err := st.ConsumeToken(ctx, token, "st.example.com", at)
		if err != nil {
			t.Fatal(err)
		}
		return email, ok
	}
	if err := st.IssueToken(ctx, "th", "st.example.com", "a@b.c", now, -2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if email, ok := consume("th", "2026-10-15T12:00:00Z"); ok {
		t.Fatalf("expired token consumed by %s", email)
	}
	if err := st.IssueToken(ctx, "th2", "st.example.com", "a@b.c", "2026-10-15T10:00:00Z", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	email, ok := consume("th2", "2026-10-15T11:01:00Z") // issued+15min = 10:15 < 11:01: expired
	if ok {
		t.Fatalf("late token consumed by %s", email)
	}
	// valid + right host
	if err := st.IssueToken(ctx, "th3", "st.example.com", "alice@x.io", now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := st.IssueToken(ctx, "th4", "other.example.com", "alice@x.io", now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	email, ok = consume("th4", "2026-10-15T10:01:00Z") // wrong host
	if ok {
		t.Fatalf("wrong-host token consumed by %s", email)
	}
	email, ok = consume("th3", "2026-10-15T10:01:00Z")
	if !ok || email != "alice@x.io" {
		t.Fatalf("right token rejected: %q %v", email, ok)
	}
	email, ok = consume("th3", "2026-10-15T10:02:00Z")
	if ok {
		t.Fatalf("replay accepted for %s", email)
	}
}

func TestTokenConcurrent(t *testing.T) {
	st := gateStore(t)
	ctx := context.Background()
	if err := st.IssueToken(ctx, "c", "st.example.com", "a@b.c", now, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	const n = 8
	res := make(chan bool, n)
	for range n {
		go func() {
			_, ok, err := st.ConsumeToken(ctx, "c", "st.example.com", "2026-10-15T10:01:00Z")
			if err != nil {
				res <- false
				return
			}
			res <- ok
		}()
	}
	won := 0
	for range n {
		if <-res {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d goroutines consumed a single-use token", won)
	}
}

func TestIdentityNonceAndDelete(t *testing.T) {
	st := gateStore(t)
	ctx := context.Background()
	if n, err := st.IdentityNonce(ctx, "a@b.c"); err != nil || n != "" {
		t.Fatalf("absent identity: %q %v", n, err)
	}
	if err := st.UpsertIdentity(ctx, "a@b.c", "n1", "h1", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n, err := st.IdentityNonce(ctx, "a@b.c"); err != nil || n != "n1" {
		t.Fatalf("nonce: %q %v", n, err)
	}
	gs, err := st.GateIdentities(ctx)
	if err != nil || len(gs) != 1 || gs[0].Email != "a@b.c" {
		t.Fatalf("identities: %+v %v", gs, err)
	}
	// Grants appear in the listing once the ACL site matches the identity's domain.
	r, _ := st.ListSites(ctx)
	if err := st.ReplaceGrants(ctx, r[0].ID, []Grant{{Mode: "domain", Value: "b.c"}}); err != nil {
		t.Fatal(err)
	}
	gs, _ = st.GateIdentities(ctx)
	if gs[0].Rules != "@b.c at st.example.com" {
		t.Fatalf("rules text: %q", gs[0].Rules)
	}
	if err := st.DeleteIdentity(ctx, "a@b.c"); err != nil {
		t.Fatal(err)
	}
	if gs, _ = st.GateIdentities(ctx); len(gs) != 0 {
		t.Fatalf("deleted identity still listed: %+v", gs)
	}
	// The identity survives a site deletion (grants cascade, identity may live elsewhere).
	if err := st.UpsertIdentity(ctx, "a@b.c", "n2", "h2", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSite(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if gs, _ = st.GateIdentities(ctx); len(gs) != 1 {
		t.Fatalf("identity lost on site delete: %+v", gs)
	}
}
