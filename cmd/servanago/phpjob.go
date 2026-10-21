package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/servanago/servanago/internal/phpbuild"
	"github.com/servanago/servanago/internal/runtimes"
)

// runPHPJob is `servanago php-job fetch|build DIR`: the PHP build job the helper's two units run as sg-phpbuild
// (see internal/helper/php.go). Output goes to stdout, which systemd sends to the journal.
func runPHPJob(args []string) error {
	if len(args) != 2 || (args[0] != "fetch" && args[0] != "build") {
		return fmt.Errorf("usage: servanago php-job fetch|build DIR")
	}
	phase, dir := args[0], filepath.Clean(args[1])
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("job directory %q must be absolute", dir)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	e := phpbuild.Env{
		Get: phpbuild.HTTPGet,
		Run: phpbuild.RunCmd,
		Verify: func(ctx context.Context, file, sig string) error {
			return phpbuild.VerifyGPG(ctx, phpbuild.Keyring, file, sig)
		},
		Root:  runtimes.PHPRoot,
		Stage: filepath.Join(dir, "root"),
		Log:   os.Stdout,
	}
	if phase == "fetch" {
		return phpbuild.Fetch(ctx, e, dir)
	}
	return phpbuild.Build(ctx, e, dir)
}
