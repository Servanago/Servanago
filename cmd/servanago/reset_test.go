package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/store"
)

func TestResetWipesFactorsWithoutOtherEnv(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "servanago.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = st.SaveTOTP(ctx, []byte("s"))
	_ = st.EnableTOTP(ctx, 1, []string{"a", "b"})
	_ = st.AddPasskey(ctx, store.Passkey{ID: "p", RPID: "h", CredentialID: []byte{1}, Credential: "{}", Name: "n"})
	st.Close()

	t.Setenv("DATA_DIR", dir)
	var out bytes.Buffer
	if err := runReset(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "totp=true backup_codes=2 passkeys=1") {
		t.Fatalf("output: %s", out.String())
	}
	st, _ = store.Open(filepath.Join(dir, "servanago.db"))
	defer st.Close()
	if _, ok, _ := st.GetTOTP(ctx); ok {
		t.Error("totp survived")
	}
}
