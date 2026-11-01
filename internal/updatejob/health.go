package updatejob

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ListenFromEnv reads UI_LISTEN from the service's env file (the last assignment wins, as in systemd) and turns
// a wildcard address into loopback. Default 127.0.0.1:8080.
func ListenFromEnv(envFile string) string {
	listen := "127.0.0.1:8080"
	if b, err := os.ReadFile(envFile); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "UI_LISTEN="); ok {
				listen = strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1:8080"
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// Health returns a check that passes when both units are active and /login answers 200 within wait.
func Health(addr string, wait, every time.Duration, run func(string, ...string) (string, error)) func() error {
	return func() error {
		deadline := time.Now().Add(wait)
		var last error
		for {
			last = probe(addr, run)
			if last == nil || time.Now().After(deadline) {
				return last
			}
			time.Sleep(every)
		}
	}
}

func probe(addr string, run func(string, ...string) (string, error)) error {
	for _, u := range []string{helperUnit, appUnit} {
		if _, err := run("systemctl", "is-active", "--quiet", u); err != nil {
			return fmt.Errorf("%s is not active", u)
		}
	}
	c := http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/login")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/login answered %s", resp.Status)
	}
	return nil
}
