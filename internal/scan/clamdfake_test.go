package scan

// fake clamd: an in-process clamd that serves PING and zINSTREAM on a real unix socket.
// Content decides the verdict, like the daemon: a stream holding the EICAR test string is
// "stream: Eicar-Test-Signature FOUND"; anything else is OK. A non-empty failWith makes every
// answer an ERROR line.

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeClamd(t *testing.T, failWith string) (socket string, calls *int) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	calls = new(int)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveClamd(c, failWith, calls)
		}
	}()
	return sock, calls
}

var eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

func serveClamd(c net.Conn, failWith string, calls *int) {
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
		*calls++
		var body []byte
		var lenBytes [4]byte
		for {
			if _, err := readFull(r, lenBytes[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(lenBytes[:])
			if n == 0 {
				break
			}
			chunk := make([]byte, n)
			if _, err := readFull(r, chunk); err != nil {
				return
			}
			body = append(body, chunk...)
		}
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

// readFull reads exactly len(p) bytes.
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

// infected writes a file whose content carries the test signature.
func infected(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("header\n"+eicar+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
