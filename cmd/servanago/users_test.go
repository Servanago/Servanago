package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/store"
)

func pw(s string) func() (string, error) { return func() (string, error) { return s, nil } }

func dataDirWith(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	st, err := store.Open(filepath.Join(dir, "servanago.db"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, st
}

func TestUserAddCreatesAnAdminFromDataDirAlone(t *testing.T) {
	dir, st := dataDirWith(t)
	st.Close()
	var out bytes.Buffer
	if err := runUser([]string{"add", "Carol"}, pw("carols-password"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "carol") {
		t.Errorf("output: %s", out.String())
	}
	st, _ = store.Open(filepath.Join(dir, "servanago.db"))
	defer st.Close()
	u, ok, _ := st.GetUserByName(context.Background(), "carol")
	if !ok || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("carols-password")) != nil {
		t.Fatalf("stored user: %+v %v", u, ok)
	}
	if rows, _ := st.ListAudit(context.Background(), 5); len(rows) != 1 || rows[0].Actor != "cli" || rows[0].Action != "user.added" || rows[0].Target != "carol" {
		t.Fatalf("audit after add: %+v", rows)
	}
	for name, args := range map[string][]string{
		"duplicate":      {"add", "CAROL"},
		"bad name":       {"add", "no spaces"},
		"no name":        {"add"},
		"extra argument": {"add", "dave", "extra"},
		"unknown verb":   {"remove", "carol"},
		"no verb":        {},
	} {
		if err := runUser(args, pw("long-enough-pw"), &out); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := runUser([]string{"add", "dave"}, pw("short"), &out); err == nil {
		t.Error("weak password accepted")
	}
	if err := runUser([]string{"add", "dave"}, func() (string, error) { return "", errors.New("no tty") }, &out); err == nil {
		t.Error("a failed password prompt created a user")
	}
	st2, _ := store.Open(filepath.Join(dir, "servanago.db"))
	defer st2.Close()
	if n, _ := st2.CountUsers(context.Background()); n != 1 {
		t.Errorf("rejected commands left users behind: %d", n)
	}
}

func TestUserPasswdChangesThePasswordAndEndsSessions(t *testing.T) {
	dir, st := dataDirWith(t)
	ctx := context.Background()
	h, _ := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
	u, _ := st.CreateUser(ctx, "erin", string(h))
	st.Close()

	var out bytes.Buffer
	if err := runUser([]string{"passwd", "ERIN"}, pw("new-password-1"), &out); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(filepath.Join(dir, "servanago.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, _ := reopened.GetUser(ctx, u.ID)
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte("new-password-1")) != nil || got.SessionEpoch != u.SessionEpoch+1 {
		t.Fatalf("after passwd: %+v", got)
	}
	if rows, _ := reopened.ListAudit(ctx, 5); len(rows) != 1 || rows[0].Actor != "cli" || rows[0].Action != "user.password" || rows[0].Target != "erin" {
		t.Fatalf("audit after passwd: %+v", rows)
	}
	if err := runUser([]string{"passwd", "nobody"}, pw("new-password-1"), &out); err == nil {
		t.Error("unknown user accepted")
	}
	if err := runUser([]string{"passwd", "erin"}, pw("short"), &out); err == nil {
		t.Error("weak password accepted")
	}
}
