package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func mustUser(t *testing.T, s *Store, name string) User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), name, "$2a$10$hash-"+name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUserCreateLookupAndUniqueness(t *testing.T) {
	s, ctx := open(t), context.Background()
	a := mustUser(t, s, "Alice")
	if a.Username != "alice" || a.SessionEpoch != 1 || len(a.WebAuthnID) != 32 || a.CreatedAt == "" {
		t.Fatalf("created: %+v", a)
	}
	if got, ok, err := s.GetUserByName(ctx, "ALICE"); err != nil || !ok || got.ID != a.ID {
		t.Fatalf("by name, case-insensitive: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := s.GetUserByName(ctx, "nobody"); ok {
		t.Error("unknown name found")
	}
	if _, err := s.CreateUser(ctx, "aLiCe", "x"); err == nil {
		t.Error("duplicate username (different case) accepted")
	}
	b := mustUser(t, s, "bob")
	if bytes.Equal(a.WebAuthnID, b.WebAuthnID) {
		t.Error("two users share a WebAuthn handle")
	}
	if got, ok, _ := s.GetUserByWebAuthnID(ctx, b.WebAuthnID); !ok || got.ID != b.ID {
		t.Errorf("by handle: %+v %v", got, ok)
	}
	if us, err := s.ListUsers(ctx); err != nil || len(us) != 2 || us[0].Username != "alice" {
		t.Fatalf("list: %+v %v", us, err)
	}
	if n, _ := s.CountUsers(ctx); n != 2 {
		t.Errorf("count %d", n)
	}
	if _, err := s.GetUser(ctx, 999); err == nil {
		t.Error("missing id found")
	}
}

func TestPasswordChangeAndEpoch(t *testing.T) {
	s, ctx := open(t), context.Background()
	u := mustUser(t, s, "alice")
	if err := s.SetPassword(ctx, u.ID, "$2a$10$new"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.PasswordHash != "$2a$10$new" || got.SessionEpoch != u.SessionEpoch+1 {
		t.Fatalf("after password change: %+v", got)
	}
	if err := s.BumpEpoch(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetUser(ctx, u.ID); got.SessionEpoch != u.SessionEpoch+2 {
		t.Fatalf("after bump: %+v", got)
	}
	if err := s.TouchLogin(ctx, u.ID, "2026-10-17T10:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetUser(ctx, u.ID); got.LastLoginAt != "2026-10-17T10:00:00Z" {
		t.Fatalf("last login: %+v", got)
	}
}

func TestDeleteUserKeepsTheLastAdminAndCascades(t *testing.T) {
	s, ctx := open(t), context.Background()
	a, b := mustUser(t, s, "alice"), mustUser(t, s, "bob")
	if err := s.SaveTOTP(ctx, b.ID, []byte("s")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPasskey(ctx, b.ID, Passkey{ID: "p", RPID: "h", CredentialID: []byte{1}, Credential: "{}", Name: "n"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetTOTP(ctx, b.ID); ok {
		t.Error("totp survived its user")
	}
	if ps, _ := s.ListPasskeys(ctx, b.ID); len(ps) != 0 {
		t.Error("passkeys survived their user")
	}
	if err := s.DeleteUser(ctx, a.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting the last admin: %v", err)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Errorf("count after refusing: %d", n)
	}
}

// Every second factor belongs to one user: the same backup code hash, a TOTP step and a reset never cross over.
func TestFactorsAreIsolatedPerUser(t *testing.T) {
	s, ctx := open(t), context.Background()
	a, b := mustUser(t, s, "alice"), mustUser(t, s, "bob")
	for _, u := range []User{a, b} {
		if err := s.SaveTOTP(ctx, u.ID, []byte("seed-"+u.Username)); err != nil {
			t.Fatal(err)
		}
		if err := s.EnableTOTP(ctx, u.ID, 10, []string{"same-hash", "x-" + u.Username}); err != nil {
			t.Fatal(err)
		}
	}
	if ta, _, _ := s.GetTOTP(ctx, a.ID); string(ta.Secret) != "seed-alice" {
		t.Fatalf("alice's seed: %q", ta.Secret)
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, a.ID, 11); !ok {
		t.Fatal("alice's step 11 refused")
	}
	if ok, _ := s.AdvanceTOTPStep(ctx, b.ID, 11); !ok {
		t.Fatal("bob's step 11 refused after alice used hers (steps are per user)")
	}
	if ok, _ := s.UseBackupCode(ctx, a.ID, "same-hash"); !ok {
		t.Fatal("alice's backup code refused")
	}
	if ok, _ := s.UseBackupCode(ctx, a.ID, "same-hash"); ok {
		t.Error("alice reused a backup code")
	}
	if ok, _ := s.UseBackupCode(ctx, b.ID, "same-hash"); !ok {
		t.Error("bob's identical code was burned by alice")
	}
	if ok, _ := s.UseBackupCode(ctx, b.ID, "x-alice"); ok {
		t.Error("bob used alice's code")
	}
	if err := s.AddPasskey(ctx, a.ID, Passkey{ID: "pa", RPID: "h", CredentialID: []byte{1}, Credential: "{}", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPasskey(ctx, b.ID, Passkey{ID: "pb", RPID: "h", CredentialID: []byte{2}, Credential: "{}", Name: "b"}); err != nil {
		t.Fatal(err)
	}
	if ps, _ := s.ListPasskeys(ctx, a.ID); len(ps) != 1 || ps[0].ID != "pa" {
		t.Fatalf("alice's passkeys: %+v", ps)
	}
	if ok, _ := s.DeletePasskey(ctx, a.ID, "pb"); ok {
		t.Error("alice deleted bob's passkey")
	}
	owner, ok, _ := s.PasskeyOwner(ctx, []byte{2})
	if !ok || owner != b.ID {
		t.Errorf("credential owner: %d %v", owner, ok)
	}

	// Resetting one user leaves the other intact.
	hadTOTP, codes, keys, err := s.ResetAuth(ctx, a.ID)
	if err != nil || !hadTOTP || codes != 2 || keys != 1 { // codes counts every row removed, used or not
		t.Fatalf("reset alice: totp=%v codes=%d keys=%d %v", hadTOTP, codes, keys, err)
	}
	if _, ok, _ := s.GetTOTP(ctx, b.ID); !ok {
		t.Error("resetting alice removed bob's authenticator")
	}
	if n, _ := s.CountBackupCodes(ctx, b.ID); n != 1 {
		t.Errorf("bob's unused codes after alice's reset: %d", n)
	}
	if ps, _ := s.ListPasskeys(ctx, b.ID); len(ps) != 1 {
		t.Error("resetting alice removed bob's passkey")
	}
}
