package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// runServeStatic serves one folder, read-only, on the socket systemd passes in (socket activation, fd 3). The
// site's unit runs it as the site's own user, so the folder never has to be readable by the control plane.
func runServeStatic(args []string) error {
	fs := flag.NewFlagSet("serve-static", flag.ContinueOnError)
	root := fs.String("root", "", "the folder to serve")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !filepath.IsAbs(*root) {
		return errors.New("serve-static: --root must be an absolute path")
	}
	ln, err := systemdListener()
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: staticHandler(*root), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// systemdListener takes the one socket systemd handed this process (LISTEN_PID names it, LISTEN_FDS is 1, fd 3).
func systemdListener() (net.Listener, error) {
	if pid, err := strconv.Atoi(os.Getenv("LISTEN_PID")); err != nil || pid != os.Getpid() || os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("serve-static: no socket from systemd (it runs from servanago-<slug>.socket)")
	}
	f := os.NewFile(3, "systemd socket")
	defer f.Close()
	return net.FileListener(f)
}

// staticHandler is Caddy's file_server for one site without its listing: GET and HEAD only, no directory listing,
// and no path with a dot-leading part (.env, .git) is ever served.
func staticHandler(root string) http.Handler {
	files := http.FileServer(noListing{http.Dir(root)})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		for _, part := range strings.Split(r.URL.Path, "/") {
			if strings.HasPrefix(part, ".") {
				http.NotFound(w, r)
				return
			}
		}
		files.ServeHTTP(w, r)
	})
}

// noListing refuses a directory that has no index.html, so FileServer never lists one.
type noListing struct{ fs http.FileSystem }

func (n noListing) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil && st.IsDir() {
		idx, err := n.fs.Open(strings.TrimSuffix(name, "/") + "/index.html")
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("no index: %w", os.ErrNotExist)
		}
		_ = idx.Close()
	}
	return f, nil
}
