package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/servanago/servanago/internal/store"
)

// openDataStore opens the database from DATA_DIR alone, so the recovery commands run without the other required
// env (the service may be down or restarting).
func openDataStore() (*store.Store, error) {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "/data"
	}
	return store.Open(filepath.Join(dir, "servanago.db"))
}

// runReset implements `servanago 2fa-reset <username>`: wipes that user's authenticator, backup codes and
// passkeys, and ends their sessions, so their password works alone again. Other users are untouched.
func runReset(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: servanago 2fa-reset <username>")
	}
	st, err := openDataStore()
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	u, ok, err := st.GetUserByName(ctx, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no user named %q", args[0])
	}
	totp, codes, keys, err := st.ResetAuth(ctx, u.ID)
	if err != nil {
		return err
	}
	if err := st.BumpEpoch(ctx, u.ID); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "2fa reset for %s: totp=%v backup_codes=%d passkeys=%d. Their open sessions have ended.\n", u.Username, totp, codes, keys)
	return err
}
