package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/buildinfo"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/update"
	"github.com/servanago/servanago/internal/updatejob"
)

// runUpdateJob is `servanago update-job`, the root unit servanago-upgrade.service the helper's update-start action
// installs and starts. It reads /var/lib/servanago-update/job.json and does the upgrade (internal/updatejob).
func runUpdateJob(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("update-job takes no arguments")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("update-job must run as root")
	}
	dir := helper.UpdateJobDir
	lock, err := updatejob.Lock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	run := realRun
	e := &updatejob.Env{
		Dir: dir, DataDir: dataDir(), Running: buildinfo.Version, Arch: runtime.GOARCH, Keys: update.Keys,
		Fetch: realFetch, Run: run, Now: time.Now,
		Health: updatejob.Health(updatejob.ListenFromEnv(defaultEnvFile), 60*time.Second, 2*time.Second, run),
	}
	res := e.Do()
	if !res.OK {
		return fmt.Errorf("upgrade %s to %s failed (rolled back: %t, needs hands: %t): %s", res.From, res.To, res.RolledBack, res.NeedsHands, res.Error)
	}
	return nil
}

func realRun(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func realFetch(url string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("%s: only https is allowed", url)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Minute}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, limit)
	}
	return b, nil
}
