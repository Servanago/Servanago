package backup

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var idNames sync.Map // "u:1000" -> name

func lookupUser(uid int) string {
	k := "u:" + strconv.Itoa(uid)
	if v, ok := idNames.Load(k); ok {
		return v.(string)
	}
	n := ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		n = u.Username
	}
	idNames.Store(k, n)
	return n
}

func lookupGroup(gid int) string {
	k := "g:" + strconv.Itoa(gid)
	if v, ok := idNames.Load(k); ok {
		return v.(string)
	}
	n := ""
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		n = g.Name
	}
	idNames.Store(k, n)
	return n
}

// OwnerFromHeader maps an entry's owner to ids on this host: by name when the user or group exists here, else the
// archived numeric id. This is the Chown hook for real restores.
func OwnerFromHeader(h *tar.Header) (uid, gid int) {
	uid, gid = h.Uid, h.Gid
	if u, err := user.Lookup(h.Uname); h.Uname != "" && err == nil {
		if n, err := strconv.Atoi(u.Uid); err == nil {
			uid = n
		}
	}
	if g, err := user.LookupGroup(h.Gname); h.Gname != "" && err == nil {
		if n, err := strconv.Atoi(g.Gid); err == nil {
			gid = n
		}
	}
	return uid, gid
}

// Extractor writes archive entries under Dest. It trusts nothing in the archive: every entry must be a directory,
// a regular file or a symlink; no setuid/setgid/sticky bits; no path may leave Dest; and no write ever passes through a symlink
// (a symlink entry is created as a link, never followed, and any later entry below it is refused).
type Extractor struct {
	Dest  string                                 // an existing directory, already symlink-resolved by the caller
	Chown func(path string, h *tar.Header) error // nil = leave the process's ownership (tests)
	// Volume skips FIFOs instead of failing: an app volume can hold one, and the app recreates it.
	Volume bool
}

// Extract writes the entry whose archive name is name (h.Name with its prefix already removed) into Dest.
func (x Extractor) Extract(name string, h *tar.Header, r io.Reader) error {
	if name == "" || name == "." {
		return nil
	}
	if strings.ContainsRune(name, 0) || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return fmt.Errorf("entry %q: absolute or invalid path", h.Name)
	}
	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("entry %q: path leaves the destination", h.Name)
	}
	target := filepath.Join(x.Dest, clean)
	if err := x.noLinksBelow(filepath.Dir(clean)); err != nil {
		return fmt.Errorf("entry %q: %w", h.Name, err)
	}
	switch h.Typeflag {
	case tar.TypeDir:
		if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if fi, err := os.Lstat(target); err != nil || !fi.IsDir() {
			return fmt.Errorf("entry %q: exists and is not a directory", h.Name)
		}
		if err := os.Chmod(target, os.FileMode(h.Mode)&0o777); err != nil {
			return err
		}
	case tar.TypeReg:
		tmp, err := os.CreateTemp(filepath.Dir(target), ".restore-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		_, cerr := io.Copy(tmp, r)
		if err := errors.Join(cerr, tmp.Chmod(os.FileMode(h.Mode)&0o777), tmp.Close()); err != nil {
			return err
		}
		if fi, err := os.Lstat(target); err == nil && fi.IsDir() {
			return fmt.Errorf("entry %q: a directory is in the way", h.Name)
		}
		if err := os.Rename(tmp.Name(), target); err != nil { // replaces a file or symlink without following it
			return err
		}
	case tar.TypeSymlink:
		if fi, err := os.Lstat(target); err == nil {
			if fi.IsDir() {
				return fmt.Errorf("entry %q: a directory is in the way", h.Name)
			}
			if err := os.Remove(target); err != nil {
				return err
			}
		}
		if err := os.Symlink(h.Linkname, target); err != nil {
			return err
		}
	case tar.TypeFifo:
		if x.Volume {
			return nil
		}
		fallthrough
	default:
		return fmt.Errorf("entry %q: type %q is not restored", h.Name, string(h.Typeflag))
	}
	if x.Chown != nil {
		return x.Chown(target, h)
	}
	return nil
}

// noLinksBelow refuses a parent chain that contains a symlink (or a non-directory) below Dest. Missing parents are
// created, so an archive that lists files without their directories still restores.
func (x Extractor) noLinksBelow(rel string) error {
	if rel == "." {
		return nil
	}
	cur := x.Dest
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() { // includes symlinks: Lstat does not follow
			return fmt.Errorf("%s is not a directory (symlinks are never followed)", part)
		}
	}
	return nil
}

// ExtractPrefix restores every entry named prefix+"…" from tr into dest, then returns. Other entries are skipped
// (their bodies are discarded by tar.Reader.Next).
func ExtractPrefix(tr *tar.Reader, prefix, dest string, chown func(string, *tar.Header) error) error {
	x := Extractor{Dest: dest, Chown: chown}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(h.Name, prefix) {
			continue
		}
		if err := x.Extract(strings.TrimPrefix(h.Name, prefix), h, tr); err != nil {
			return err
		}
	}
}

func ownerOf(fi os.FileInfo) (uid, gid int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}
