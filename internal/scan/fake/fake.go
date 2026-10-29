// Package fake runs an in-process clamd on a real unix socket for tests in any package.
// Content decides the verdict, like the daemon: a stream holding the EICAR test string answers
// "stream: Eicar-Test-Signature FOUND", anything else OK; failWith turns every answer into an
// ERROR line. internal/scan's own tests double as this helper's tests.
package fake

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Clamd starts the fake daemon and returns its socket path. failWith != "" answers every
// stream with that error line; calls() counts the streams it received.
func Clamd(t testing.TB, failWith string) (socket string, calls func() int) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveClamd(c, failWith, &n)
		}
	}()
	return sock, func() int { return int(n.Load()) }
}

const eicarPrefix = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

func serveClamd(c net.Conn, failWith string, n *atomic.Int64) {
	defer c.Close()
	r := bufio.NewReader(c)
	line, err := r.ReadString('\x00')
	if err != nil {
		return
	}
	switch cmd := strings.TrimSuffix(line, "\x00"); {
	case cmd == "zPING":
		_, _ = c.Write([]byte("PONG\n"))
	case cmd == "zINSTREAM":
		var body []byte
		var lenBytes [4]byte
		for {
			if _, err := readFull(r, lenBytes[:]); err != nil {
				return
			}
			if sz := binary.BigEndian.Uint32(lenBytes[:]); sz == 0 {
				break
			}
			chunk := make([]byte, binary.BigEndian.Uint32(lenBytes[:]))
			if _, err := readFull(r, chunk); err != nil {
				return
			}
			body = append(body, chunk...)
		}
		n.Add(1)
		switch {
		case failWith != "":
			_, _ = c.Write([]byte(failWith + "\n"))
		case strings.Contains(string(body), "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"):
			_, _ = c.Write([]byte("stream: Eicar-Test-Signature FOUND\n"))
		default:
			_, _ = c.Write([]byte("OK\n"))
		}
	default:
		_, _ = c.Write([]byte("UNKNOWN COMMAND\n"))
	}
}

func readFull(r *bufio.Reader, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := r.Read(p[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Infected writes a file whose content carries the test signature at root/name, creating the dir.
func Infected(t testing.TB, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("header\n"+eicarPrefix+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
