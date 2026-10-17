package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func TestResetWipesOneUsersFactorsWithoutOtherEnv(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "servanago.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	alice, _ := st.CreateUser(ctx, "alice", "h")
	bob, _ := st.CreateUser(ctx, "bob", "h")
	for _, u := range []store.User{alice, bob} {
		_ = st.SaveTOTP(ctx, u.ID, []byte("s"))
		_ = st.EnableTOTP(ctx, u.ID, 1, []string{"a", "b"})
	}
	_ = st.AddPasskey(ctx, alice.ID, store.Passkey{ID: "p", RPID: "h", CredentialID: []byte{1}, Credential: "{}", Name: "n"})
	st.Close()

	t.Setenv("DATA_DIR", dir)
	var out bytes.Buffer
	if err := runReset([]string{"Alice"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "totp=true backup_codes=2 passkeys=1") || !strings.Contains(out.String(), "alice") {
		t.Fatalf("output: %s", out.String())
	}
	st, _ = store.Open(filepath.Join(dir, "servanago.db"))
	defer st.Close()
	if _, ok, _ := st.GetTOTP(ctx, alice.ID); ok {
		t.Error("alice's totp survived")
	}
	if _, ok, _ := st.GetTOTP(ctx, bob.ID); !ok {
		t.Error("bob's totp was removed by alice's reset")
	}
	if got, _ := st.GetUser(ctx, alice.ID); got.SessionEpoch != alice.SessionEpoch+1 {
		t.Errorf("alice's sessions not ended: epoch %d (was %d)", got.SessionEpoch, alice.SessionEpoch)
	}
	if err := runReset([]string{"nobody"}, &out); err == nil {
		t.Error("unknown user accepted")
	}
	if err := runReset(nil, &out); err == nil {
		t.Error("missing username accepted")
	}
}
