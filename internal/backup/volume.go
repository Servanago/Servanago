package backup

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// restoreVolumes replaces the contents of the named volumes from the archive. The containers that mount them and are
// running get stopped first and started again on every exit path; the volume is emptied only after they are confirmed
// down.
func restoreVolumes(e Env, archive string, volumes []string) (err error) {
	dirs := map[string]string{}
	var running []Container
	seen := map[string]bool{}
	for _, v := range volumes {
		d, err := e.Volume(v)
		if err != nil {
			return err
		}
		if strings.Count(filepath.Clean(d), "/") < 3 { // ponytail: DockerVolume pins the real shape; this keeps a bad seam from clearing "/" or /var
			return fmt.Errorf("volume %s: directory %q is too close to the root", v, d)
		}
		dirs[v] = d
		cs, err := e.Users(v)
		if err != nil {
			return fmt.Errorf("volume %s: containers: %w", v, err)
		}
		for _, c := range cs {
			if c.Running && !seen[c.ID] {
				seen[c.ID] = true
				running = append(running, c)
			}
		}
	}
	var stopped []Container
	defer func() {
		for i := len(stopped) - 1; i >= 0; i-- {
			if serr := e.Start(stopped[i].ID); serr != nil {
				err = errors.Join(err, fmt.Errorf("start %s: %w", stopped[i].Name, serr))
				continue
			}
			slog.Info("backup restore: container started", "container", stopped[i].Name)
		}
	}()
	for _, c := range running {
		stopped = append(stopped, c) // before Stop: a container that half-stopped is started again too
		if err := e.Stop(c.ID); err != nil {
			return fmt.Errorf("stop %s: %w", c.Name, err)
		}
		slog.Info("backup restore: container stopped", "container", c.Name)
	}
	for _, c := range stopped {
		up, err := e.IsRunning(c.ID)
		if err != nil {
			return fmt.Errorf("container %s: %w", c.Name, err)
		}
		if up {
			return fmt.Errorf("container %s is running again; nothing was changed", c.Name)
		}
	}
	tr, closeFn, err := Open(archive, e.Pass)
	if err != nil {
		return err
	}
	defer func() { _ = closeFn() }()
	cleared := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		for _, v := range volumes {
			pre := "volumes/" + v + "/"
			if !strings.HasPrefix(h.Name, pre) {
				continue
			}
			if !cleared[v] {
				if err := clearDir(dirs[v]); err != nil {
					return fmt.Errorf("volume %s: %w", v, err)
				}
				cleared[v] = true
			}
			x := Extractor{Dest: dirs[v], Chown: e.VolumeChown, Volume: true}
			if err := x.Extract(strings.TrimPrefix(h.Name, pre), h, tr); err != nil {
				return fmt.Errorf("volume %s is partly restored: %w", v, err)
			}
		}
	}
	for _, v := range volumes {
		if !cleared[v] {
			return fmt.Errorf("the archive has no entries for volume %s", v)
		}
	}
	return nil
}

// clearDir removes everything inside dir and keeps dir itself (a mount point).
func clearDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, en := range ents {
		if err := os.RemoveAll(filepath.Join(dir, en.Name())); err != nil {
			return err
		}
	}
	return nil
}
