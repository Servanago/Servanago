package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/buildinfo"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/update"
	"github.com/servanago/servanago/internal/updatejob"
)

// updater is `servanago update` with its host seams, so the command runs against fakes in tests.
type updater struct {
	version string
	keys    []ed25519.PublicKey
	fetch   func(url string, limit int64) ([]byte, error)
	start   func(helper.Spec) error
	dir     string // the job's state directory
	in      io.Reader
	out     io.Writer
	wait    time.Duration // between looks at the job's state file
	giveUp  time.Duration // how long to wait for a job that never reports
}

func runUpdate(args []string, in io.Reader, out io.Writer) error {
	return (&updater{
		version: buildinfo.Version, keys: update.Keys, fetch: realFetch, dir: helper.UpdateJobDir, in: in, out: out,
		wait: 2 * time.Second, giveUp: 30 * time.Minute,
		start: func(sp helper.Spec) error {
			_, err := helper.NewClient(helper.SocketPath).Call(context.Background(), helper.ActionUpdateStart, sp)
			return err
		},
	}).run(args)
}

var sudoUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (u *updater) run(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "only report whether a newer release exists")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mf, err := u.fetch(update.ManifestURL, 64<<10)
	if err != nil {
		return fmt.Errorf("release manifest: %w", err)
	}
	sig, err := u.fetch(update.SigURL, 64<<10)
	if err != nil {
		return fmt.Errorf("release manifest signature: %w", err)
	}
	m, err := update.Verify(u.keys, mf, sig)
	if err != nil {
		return err
	}
	fmt.Fprintf(u.out, "running %s, latest %s\n", u.version, m.Version)
	if !update.Newer(u.version, m.Version) {
		if u.version == "dev" {
			fmt.Fprintln(u.out, "this is a build from source; it is never upgraded from here")
			return nil
		}
		fmt.Fprintln(u.out, "up to date")
		return nil
	}
	fmt.Fprintf(u.out, "notes: %s\n", m.NotesURL)
	if m.SchemaChange {
		fmt.Fprintln(u.out, "this release applies a database migration")
	}
	if m.Breaking {
		fmt.Fprintln(u.out, "this release is breaking: read the notes first")
	}
	if *check {
		return nil
	}
	if !*yes {
		fmt.Fprintf(u.out, "install %s now? the panel restarts for about a minute [y/N] ", m.Version)
		line, _ := bufio.NewReader(u.in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("not confirmed; nothing changed")
		}
	}
	actor := os.Getenv("SUDO_USER")
	if !sudoUserRE.MatchString(actor) {
		actor = "root"
	}
	began := time.Now()
	if err := u.start(helper.Spec{UpdateVersion: m.Version, Actor: actor}); err != nil {
		return err
	}
	return u.follow(began)
}

// result is this run's outcome: result.json, or result.json.seen once the restarted panel has audited it. An older
// run's file is ignored.
func (u *updater) result(began time.Time) (res updatejob.Result, ok bool) {
	for _, n := range []string{"result.json", "result.json.seen"} {
		b, err := os.ReadFile(filepath.Join(u.dir, n))
		if err != nil || json.Unmarshal(b, &res) != nil {
			continue
		}
		if at, err := time.Parse(time.RFC3339, res.At); err == nil && !at.Before(began.Add(-2*time.Second)) {
			return res, true
		}
	}
	return res, false
}

// follow prints the job's phases until it reports. The job runs as its own unit, so this only reads its files.
func (u *updater) follow(began time.Time) error {
	last := ""
	deadline := time.Now().Add(u.giveUp)
	for time.Now().Before(deadline) {
		if res, ok := u.result(began); ok {
			switch {
			case res.OK:
				fmt.Fprintf(u.out, "upgraded %s to %s\n", res.From, res.To)
				return nil
			case res.NeedsHands:
				return fmt.Errorf("the upgrade failed and so did the rollback; see %s/NEEDS_HANDS.txt: %s", u.dir, res.Error)
			case res.RolledBack:
				return fmt.Errorf("the upgrade failed and %s was put back: %s", res.From, res.Error)
			}
			return fmt.Errorf("the upgrade did not start: %s", res.Error)
		}
		var st updatejob.State
		if b, err := os.ReadFile(filepath.Join(u.dir, "state.json")); err == nil && json.Unmarshal(b, &st) == nil && st.Phase != last {
			last = st.Phase
			fmt.Fprintf(u.out, "%s %s\n", st.Phase, st.Message)
		}
		time.Sleep(u.wait)
	}
	return errors.New("no result from the upgrade job; check `journalctl -u servanago-upgrade`")
}
