package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/servanago/servanago/internal/store"
)

// runReset implements `servanago 2fa-reset`: wipes TOTP, backup codes and passkeys so the password works alone.
// It reads only DATA_DIR, so it runs without the other required env (the container may be down or restarting).
func runReset(out io.Writer) error {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "/data"
	}
	st, err := store.Open(filepath.Join(dir, "servanago.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	totp, codes, keys, err := st.ResetAuth(context.Background())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "2fa reset: totp=%v backup_codes=%d passkeys=%d. Restart servanago to end live sessions.\n", totp, codes, keys)
	return err
}
