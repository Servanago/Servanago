package backup

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// Archive layout: <dir>/<scope>/<scope>-<UTC>.tar.zst.age plus <name>.json (the sidecar, no secrets). Inside the tar:
// manifest.json first, then files/, dumps/, volumes/<name>/ or panel/.

// Part is one piece of an archive; SHA256 is of the plaintext and set for dumps and single files.
type Part struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // files | dump | volume | panel
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
}

// Manifest describes an archive. The copy inside the tar carries everything but Parts and ArchiveSHA, which are known
// only at the end and live in the sidecar.
type Manifest struct {
	Scope      string    `json:"scope"`
	RunID      string    `json:"run_id"`
	Trigger    string    `json:"trigger"`
	Host       string    `json:"host"`
	Version    string    `json:"version"`
	Schema     int       `json:"schema"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished,omitempty"`
	Profiles   []string  `json:"profiles,omitempty"`
	Volumes    []string  `json:"volumes,omitempty"`
	Parts      []Part    `json:"parts,omitempty"`
	ArchiveSHA string    `json:"archive_sha256,omitempty"`
	Scanned    int       `json:"scanned,omitempty"`  // files the virus scan streamed (0 = no scan ran)
	ScanBad    int       `json:"scan_bad,omitempty"` // scanned files whose check could not run
	Infected   []string  `json:"infected,omitempty"` // "path — virus": skipped from the archive
}

const (
	archiveExt = ".tar.zst.age"
	tsLayout   = "20060102T150405Z"
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}-\d{8}T\d{6}Z\.tar\.zst\.age$`)

// ValidName reports whether name is an archive file name of this feature (no path, no traversal).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// ArchiveName is the file name for a scope at a time.
func ArchiveName(scope string, at time.Time) string {
	return scope + "-" + at.UTC().Format(tsLayout) + archiveExt
}

// Builder adds parts to an archive being written.
// Builder accumulates the archive and the scan verdicts the seam collected.
type Builder struct {
	tw       *tar.Writer
	scratch  string
	Scan     func(path string) (virus string, err error)
	Scanned  int      // files a scan saw (0 without a seam)
	ScanBad  int      // scan calls that could not run (daemon down): the file is archived anyway
	Infected []string // "path — virus": skipped from the archive, listed in the manifest
	Parts    []Part
}

func (b *Builder) addBytes(name string, data []byte, mode int64) error {
	if err := b.tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: time.Now(), Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err := b.tw.Write(data)
	return err
}

// AddReader spools r to the scratch directory (a tar header needs the size first), then writes it as one part.
func (b *Builder) AddReader(name, kind string, r io.Reader) error {
	f, err := os.CreateTemp(b.scratch, "spool-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := b.tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: n, ModTime: time.Now(), Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := io.Copy(b.tw, f); err != nil {
		return err
	}
	b.Parts = append(b.Parts, Part{Name: name, Kind: kind, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

// AddFile stores one regular file under name, keeping its mode and owner.
func (b *Builder) AddFile(name, kind, path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	h.Name, h.Format = name, tar.FormatPAX
	own(h, fi)
	if err := b.tw.WriteHeader(h); err != nil {
		return err
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(b.tw, sum), f)
	if err != nil {
		return err
	}
	b.Parts = append(b.Parts, Part{Name: name, Kind: kind, Bytes: n, SHA256: hex.EncodeToString(sum.Sum(nil))})
	return nil
}

// own records the owner by id and name.
func own(h *tar.Header, fi fs.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		h.Uid, h.Gid = int(st.Uid), int(st.Gid)
		h.Uname, h.Gname = lookupUser(h.Uid), lookupGroup(h.Gid)
	}
}

// AddTree stores a directory tree under prefix/ (directories, regular files and symlinks; sockets, devices and fifos
// are skipped). A file that vanishes or turns unreadable while the walk runs fails the part: a partial copy is not a backup.
func (b *Builder) AddTree(prefix, kind, root string) error {
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		name := prefix + "/" + filepath.ToSlash(rel)
		if rel == "." {
			name = prefix + "/"
		}
		var link string
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		case !fi.IsDir() && !fi.Mode().IsRegular():
			return nil
		}
		// the scan runs before any tar bytes: a verdicted hit skips header AND body
		if fi.Mode().IsRegular() && b.Scan != nil {
			virus, serr := b.Scan(path)
			if serr != nil {
				b.ScanBad++ // best effort at backup time: the file is archived, the count says so
			} else if virus != "" {
				b.Infected = append(b.Infected, name+" — "+virus)
				return nil
			}
			b.Scanned++
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		h.Name, h.Format = name, tar.FormatPAX
		if fi.IsDir() && !strings.HasSuffix(h.Name, "/") {
			h.Name += "/"
		}
		own(h, fi)
		if err := b.tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			n, err := io.Copy(b.tw, f)
			total += n
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if n != fi.Size() {
				return fmt.Errorf("%s changed size while it was read", path)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	b.Parts = append(b.Parts, Part{Name: prefix + "/", Kind: kind, Bytes: total})
	return nil
}

// CreateOpts carries what Create needs besides the content.
type CreateOpts struct {
	Dir     string // backup directory
	Scratch string // temp directory for spooled parts
	Pass    string
	Chgrp   func(path string) error // gives the files to the service group; nil = leave as is
	Scan    func(path string) (virus string, err error)
}

// Create writes an encrypted archive and its sidecar atomically: the archive is renamed into place last, so a listed
// archive is always complete. m's Parts, Finished, ArchiveSHA and scan results are filled in. On any error nothing is left behind.
// The finished manifest returns so the caller can carry the scan counts into its Result.
func Create(o CreateOpts, m Manifest, fill func(*Builder) error) (name string, written int64, mf Manifest, err error) {
	dir := filepath.Join(o.Dir, m.Scope)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", 0, Manifest{}, err
	}
	if o.Chgrp != nil {
		for _, d := range []string{o.Dir, dir} {
			if err := o.Chgrp(d); err != nil {
				return "", 0, Manifest{}, err
			}
		}
	}
	name = ArchiveName(m.Scope, m.Started)
	final, side := filepath.Join(dir, name), filepath.Join(dir, name+".json")
	if _, serr := os.Lstat(final); serr == nil { // a rename would silently replace it
		return "", 0, Manifest{}, fmt.Errorf("%s already exists", name)
	}
	f, err := os.OpenFile(final+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return "", 0, Manifest{}, err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(final + ".part")
			os.Remove(side + ".part")
		}
	}()
	rec, err := age.NewScryptRecipient(o.Pass)
	if err != nil {
		return "", 0, Manifest{}, err
	}
	sum := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, sum)}
	aw, err := age.Encrypt(cw, rec)
	if err != nil {
		return "", 0, Manifest{}, err
	}
	zw, err := zstd.NewWriter(aw)
	if err != nil {
		return "", 0, Manifest{}, err
	}
	tw := tar.NewWriter(zw)
	b := &Builder{tw: tw, scratch: o.Scratch, Scan: o.Scan}
	head := m
	head.Parts, head.ArchiveSHA, head.Finished = nil, "", time.Time{}
	hb, _ := json.Marshal(head)
	if err = b.addBytes("manifest.json", hb, 0o600); err != nil {
		return "", 0, Manifest{}, err
	}
	if err = fill(b); err != nil {
		return "", 0, Manifest{}, err
	}
	for _, c := range []io.Closer{tw, zw, aw} {
		if err = c.Close(); err != nil {
			return "", 0, Manifest{}, err
		}
	}
	if err = f.Sync(); err != nil {
		return "", 0, Manifest{}, err
	}
	if err = f.Close(); err != nil {
		return "", 0, Manifest{}, err
	}
	m.Parts, m.ArchiveSHA, m.Finished = b.Parts, hex.EncodeToString(sum.Sum(nil)), time.Now().UTC()
	m.Scanned, m.ScanBad, m.Infected = b.Scanned, b.ScanBad, b.Infected
	sb, _ := json.MarshalIndent(m, "", "  ")
	if err = os.WriteFile(side+".part", sb, 0o640); err != nil {
		return "", 0, Manifest{}, err
	}
	if o.Chgrp != nil {
		if err = errors.Join(o.Chgrp(final+".part"), o.Chgrp(side+".part")); err != nil {
			return "", 0, Manifest{}, err
		}
	}
	if err = os.Rename(side+".part", side); err != nil {
		return "", 0, Manifest{}, err
	}
	if err = os.Rename(final+".part", final); err != nil {
		os.Remove(side)
		return "", 0, Manifest{}, err
	}
	return name, cw.n, m, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Sidecar reads an archive's sidecar.
func Sidecar(path string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(path + ".json")
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// Open decrypts and decompresses an archive for reading. Check the checksum with VerifyChecksum first.
func Open(path, pass string) (*tar.Reader, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	id, err := age.NewScryptIdentity(pass)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	ar, err := age.Decrypt(f, id)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("decrypt %s: %w", filepath.Base(path), err)
	}
	zr, err := zstd.NewReader(ar)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return tar.NewReader(zr), func() error { zr.Close(); return f.Close() }, nil
}

// VerifyChecksum compares the file's SHA-256 with its sidecar.
func VerifyChecksum(path string) (Manifest, error) {
	m, err := Sidecar(path)
	if err != nil {
		return m, fmt.Errorf("sidecar: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return m, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.ArchiveSHA {
		return m, fmt.Errorf("%s: checksum %s does not match the sidecar", filepath.Base(path), got)
	}
	return m, nil
}

// Verify checks the checksum, then decrypts and reads the whole archive and checks each recorded part hash.
func Verify(path, pass string) (Manifest, error) {
	m, err := VerifyChecksum(path)
	if err != nil {
		return m, err
	}
	tr, closeFn, err := Open(path, pass)
	if err != nil {
		return m, err
	}
	defer func() { _ = closeFn() }()
	want := map[string]string{}
	for _, p := range m.Parts {
		if p.SHA256 != "" {
			want[p.Name] = p.SHA256
		}
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("read archive: %w", err)
		}
		sum := sha256.New()
		if _, err := io.Copy(sum, tr); err != nil {
			return m, fmt.Errorf("read %s: %w", h.Name, err)
		}
		if w, ok := want[h.Name]; ok {
			if hex.EncodeToString(sum.Sum(nil)) != w {
				return m, fmt.Errorf("%s: content does not match its recorded hash", h.Name)
			}
			delete(want, h.Name)
		}
	}
	for n := range want {
		return m, fmt.Errorf("%s is missing from the archive", n)
	}
	return m, nil
}

// Info is one listed archive.
type Info struct {
	Name     string
	Bytes    int64
	Manifest Manifest
	Damaged  string // why the pair is unusable; "" = fine
}

// List returns a scope's archives, newest first. An archive without a readable sidecar, or the reverse, is Damaged.
func List(dir, scope string) ([]Info, error) {
	ents, err := os.ReadDir(filepath.Join(dir, scope))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, e := range ents {
		have[e.Name()] = true
	}
	var out []Info
	for _, e := range ents {
		n := e.Name()
		switch {
		case ValidName(n):
			in := Info{Name: n}
			if fi, err := e.Info(); err == nil {
				in.Bytes = fi.Size()
			}
			m, err := Sidecar(filepath.Join(dir, scope, n))
			switch {
			case err != nil:
				in.Damaged = "no readable sidecar"
				if t, e2 := time.Parse(tsLayout, strings.TrimSuffix(strings.TrimPrefix(n, scope+"-"), archiveExt)); e2 == nil {
					in.Manifest.Started = t
				}
			case m.Scope != scope:
				in.Damaged = "sidecar names another scope"
			default:
				in.Manifest = m
			}
			out = append(out, in)
		case strings.HasSuffix(n, archiveExt+".json") && !have[strings.TrimSuffix(n, ".json")]:
			out = append(out, Info{Name: strings.TrimSuffix(n, ".json"), Damaged: "sidecar without an archive"})
		}
	}
	for i := 1; i < len(out); i++ { // newest first; names embed the UTC time
		for j := i; j > 0 && out[j].Name > out[j-1].Name; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// Last is the start time of a scope's newest intact archive (zero when none).
func Last(dir, scope string) time.Time {
	ins, _ := List(dir, scope)
	for _, in := range ins {
		if in.Damaged == "" {
			return in.Manifest.Started
		}
	}
	return time.Time{}
}

// PruneScope deletes archives retention drops. Damaged pairs are neither counted nor deleted.
func PruneScope(dir, scope string, keep, weekly int) ([]string, error) {
	ins, err := List(dir, scope)
	if err != nil {
		return nil, err
	}
	var es []Entry
	for _, in := range ins {
		if in.Damaged == "" {
			es = append(es, Entry{in.Name, in.Manifest.Started})
		}
	}
	var gone []string
	for _, e := range Prune(es, keep, weekly) {
		p := filepath.Join(dir, scope, e.Name)
		if err := errors.Join(os.Remove(p+".json"), os.Remove(p)); err != nil {
			return gone, err
		}
		gone = append(gone, e.Name)
	}
	return gone, nil
}
