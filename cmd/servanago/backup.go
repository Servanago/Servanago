package main

import (
	"archive/tar"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/backup"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/store"
)

const backupUsage = `usage:
  servanago backup run [--scope all|panel|SLUG]
  servanago backup list [panel|SLUG]
  servanago backup verify ARCHIVE [--passphrase-file FILE|-]
  servanago backup restore --site SLUG ARCHIVE_NAME [--files] [--dumps]
  servanago backup restore --panel ARCHIVE [--passphrase-file FILE|-] [--env-file PATH]
Run as root on the server. The panel restore needs the service stopped and works on a fresh host: install the package,
stop servanago, restore, start. The passphrase defaults to the one stored in the panel database.`

// runBackup is `servanago backup ...`, the same code the job runs, usable with the web UI down.
func runBackup(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(backupUsage)
	}
	ctx := context.Background()
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("backup run", flag.ContinueOnError)
		scope := fs.String("scope", "all", "all, panel or a site slug")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		j, cleanup, err := openJob(dataDir(), defaultEnvFile)
		if err != nil {
			return err
		}
		defer cleanup()
		req := &helper.BackupRequestData{Op: "run", Scope: "site", Slug: *scope, Actor: "cli"}
		if *scope == "all" || *scope == "panel" {
			req.Scope, req.Slug = *scope, ""
		}
		failed, err := j.execute(ctx, req)
		if err != nil {
			return err
		}
		if failed {
			return errors.New("one or more backups failed")
		}
		fmt.Fprintln(out, "done")
		return nil
	case "list":
		j, cleanup, err := openJob(dataDir(), defaultEnvFile)
		if err != nil {
			return err
		}
		defer cleanup()
		scopes := args[1:]
		if len(scopes) == 0 {
			ents, _ := os.ReadDir(j.set.Dir)
			for _, e := range ents {
				if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					scopes = append(scopes, e.Name())
				}
			}
		}
		for _, s := range scopes {
			ins, err := backup.List(j.set.Dir, s)
			if err != nil {
				return err
			}
			for _, in := range ins {
				note := in.Manifest.Started.Local().Format(time.DateTime)
				if in.Damaged != "" {
					note = "DAMAGED: " + in.Damaged
				}
				fmt.Fprintf(out, "%s/%s\t%d bytes\t%s\n", s, in.Name, in.Bytes, note)
			}
		}
		return nil
	case "verify":
		fs := flag.NewFlagSet("backup verify", flag.ContinueOnError)
		pf := fs.String("passphrase-file", "", "file with the passphrase, - for stdin")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
			return errors.New(backupUsage)
		}
		pass, err := passphraseFor(*pf, stdin)
		if err != nil {
			return err
		}
		m, err := backup.Verify(fs.Arg(0), pass)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "ok: %s, %d parts, started %s\n", m.Scope, len(m.Parts), m.Started.Local().Format(time.DateTime))
		return nil
	case "restore":
		return runBackupRestore(ctx, args[1:], stdin, out)
	}
	return errors.New(backupUsage)
}

// passphraseFor reads the named file, or falls back to the stored passphrase.
func passphraseFor(file string, stdin io.Reader) (string, error) {
	if file != "" {
		return readPassphrase(file, stdin)
	}
	j, cleanup, err := openJob(dataDir(), defaultEnvFile)
	if err != nil {
		return "", fmt.Errorf("no --passphrase-file and the stored one is unavailable: %w", err)
	}
	defer cleanup()
	return j.passphrase()
}

func runBackupRestore(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	site := fs.String("site", "", "restore this site")
	panel := fs.Bool("panel", false, "restore the panel")
	files := fs.Bool("files", false, "restore the site's files")
	dumps := fs.Bool("dumps", false, "restore the site's database dumps")
	pf := fs.String("passphrase-file", "", "file with the passphrase, - for stdin")
	envf := fs.String("env-file", defaultEnvFile, "where the panel restore writes the environment file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || (*site == "") == !*panel {
		return errors.New(backupUsage)
	}
	if *panel {
		pass, err := panelPassphrase(*pf, stdin)
		if err != nil {
			return err
		}
		var chown func(string, *tar.Header) error
		if os.Geteuid() == 0 {
			chown = lchownFromHeader
		}
		if err := backup.RestorePanel(fs.Arg(0), pass, dataDir(), *envf, store.LatestVersion(), chown); err != nil {
			return err
		}
		fmt.Fprintln(out, "panel restored; start servanago")
		return nil
	}
	j, cleanup, err := openJob(dataDir(), defaultEnvFile)
	if err != nil {
		return err
	}
	defer cleanup()
	pass, err := j.passphrase()
	if *pf != "" {
		pass, err = readPassphrase(*pf, stdin)
	}
	if err != nil {
		return err
	}
	j.env.Pass = pass
	s, err := j.siteBySlug(ctx, *site)
	if err != nil {
		return err
	}
	p, err := j.sitePlan(ctx, s)
	if err != nil {
		return err
	}
	if !*files && !*dumps {
		return errors.New("choose --files, --dumps or both")
	}
	if err := backup.RestoreSite(ctx, j.env, p.Plan, filepath.Base(fs.Arg(0)), *files, *dumps); err != nil {
		return err
	}
	fmt.Fprintln(out, "site restored")
	return nil
}

// panelPassphrase: on a fresh host there is no database to read it from, so a file or stdin is required then.
func panelPassphrase(file string, stdin io.Reader) (string, error) {
	if file != "" {
		return readPassphrase(file, stdin)
	}
	return passphraseFor("", stdin)
}
