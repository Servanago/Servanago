package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// auditCLI records a command-line action; it runs on the server, so the actor is "cli" and there is no client address.
// A failure to write the row does not undo the action.
func auditCLI(ctx context.Context, st *store.Store, action, target string) {
	e := store.AuditEntry{At: time.Now().UTC().Format(time.RFC3339), Actor: "cli", Action: action, Target: target}
	if err := st.AddAudit(ctx, e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write the audit row: %v\n", err)
	}
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
	auditCLI(ctx, st, "user.2fa_reset", u.Username)
	_, err = fmt.Fprintf(out, "2fa reset for %s: totp=%v backup_codes=%d passkeys=%d. Their open sessions have ended.\n", u.Username, totp, codes, keys)
	return err
}
