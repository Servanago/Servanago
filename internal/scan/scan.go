// Package scan drives ClamAV's clamd daemon over its socket and quarantines what it finds.
// The daemon owns its signatures and its limits; ServanaGo never installs, updates or configures it.
package scan

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Client speaks the clamd protocol on one unix socket.
//
//	PING → PONG; zINSTREAM\0 followed by 4-byte big-endian chunk lengths, ended by a zero
//	length, answered by one line: "OK", "stream: <signature> FOUND" or an ERROR line.
type Client struct{ socket string }

func New(socket string) *Client { return &Client{socket: socket} }

// replyDeadline bounds one clamd round trip; the defaults keep a stuck daemon from stalling a sweep.
const replyDeadline = 60 * time.Second

func (c *Client) roundTrip(ctx context.Context, cmd string) (string, error) {
	conn, err := dial(ctx, c.socket)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if !c.wait(ctx, conn) {
		return "", fmt.Errorf("clamd timeout")
	}
	if _, err := conn.Write([]byte(cmd)); err != nil { // commands carry their own NUL terminator
		return "", fmt.Errorf("write to clamd: %w", err)
	}
	reply, err := readLine(conn)
	if err != nil {
		return "", fmt.Errorf("read from clamd: %w", err)
	}
	return reply, nil
}

// wait applies the deadline; the connection is closed by the caller either way.
func (c Client) wait(ctx context.Context, conn net.Conn) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(replyDeadline)
	}
	return conn.SetDeadline(deadline) == nil
}

func readLine(conn net.Conn) (string, error) {
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// Ping is the health check the scan page and settings save call.
func (c *Client) Ping(ctx context.Context) error {
	reply, err := c.roundTrip(ctx, "zPING\x00")
	if err != nil {
		return err
	}
	if reply != "PONG" {
		return fmt.Errorf("clamd answered %q, not PONG", reply)
	}
	return nil
}

// Verdict is what one streamed file produced.
type Verdict struct {
	Clean  bool
	Virus  string
	TooBig bool // larger than maxStream: never streamed, counted as skipped
	Err    string
}

// zINSTREAM chunks at 64 KiB: the protocol wants lengths ≤ the daemon's StreamMaxChunkSize.
const chunkSize = 64 << 10

// maxStream is clamd's default StreamMaxLength; larger files are never streamed.
const maxStream = 100 << 20

// ScanFile streams one file through clamd and reports the verdict.
func (c *Client) ScanFile(ctx context.Context, path string) (Verdict, error) {
	conn, err := dial(ctx, c.socket)
	if err != nil {
		return Verdict{}, err
	}
	defer conn.Close()
	if !c.wait(ctx, conn) {
		return Verdict{}, fmt.Errorf("clamd timeout")
	}
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return Verdict{}, fmt.Errorf("write to clamd: %w", err)
	}
	f, err := os.Open(path)
	if err != nil { // unreadable: count it skipped, not fatal
		return Verdict{TooBig: false, Err: "unreadable"}, nil
	}
	defer f.Close()
	buf := make([]byte, chunkSize)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			var lenBytes [4]byte
			binary.BigEndian.PutUint32(lenBytes[:], uint32(n))
			if _, err := conn.Write(lenBytes[:]); err != nil {
				return Verdict{}, fmt.Errorf("write to clamd: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return Verdict{}, fmt.Errorf("write to clamd: %w", err)
			}
		}
		if rerr != nil {
			break
		}
	}
	var zero [4]byte
	if _, err := conn.Write(zero[:]); err != nil {
		return Verdict{}, fmt.Errorf("end the stream: %w", err)
	}
	reply, err := readLine(conn)
	if err != nil {
		return Verdict{}, fmt.Errorf("read the verdict: %w", err)
	}
	return verdictOf(reply), nil
}

func dial(ctx context.Context, socket string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("clamd socket %s: %w", socket, err)
	}
	return conn, nil
}

func verdictOf(reply string) Verdict {
	switch {
	case reply == "OK":
		return Verdict{Clean: true}
	case strings.HasPrefix(reply, "stream: ") && strings.HasSuffix(reply, " FOUND"):
		return Verdict{Virus: strings.TrimSuffix(strings.TrimPrefix(reply, "stream: "), " FOUND")}
	case strings.Contains(reply, "size limit exceeded"):
		return Verdict{TooBig: true}
	default:
		return Verdict{Err: reply}
	}
}

// TreeResult reports how many files were checked and why some were skipped; the caller decides
// a run's error state from the returned error and Errs.
type TreeResult struct {
	Files   int
	Skipped int
	Errs    []string
}

// ScanTree walks root and streams every regular file; hit is called immediately per finding.
// Unreadable paths, symlinks and oversized files are skipped, not fatal; a hit callback error
// aborts the walk.
func (c *Client) ScanTree(ctx context.Context, root string, hit func(path, virus string) error) (TreeResult, error) {
	var res TreeResult
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil { // unreadable directory entry: skip it, keep scanning
			res.Skipped++
			note(&res, p+": "+werr.Error())
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() { // links are not served content
			res.Skipped++
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > maxStream {
			res.Skipped++
			note(&res, p+" over "+sizeText(maxStream))
			return nil
		}
		v, err := c.ScanFile(ctx, p)
		switch {
		case err != nil:
			return err
		case v.Clean:
			res.Files++
			return nil
		case v.TooBig:
			res.Skipped++
			return nil
		case v.Virus != "":
			res.Files++
			return hit(p, v.Virus)
		default:
			note(&res, p+": "+v.Err)
			return nil
		}
	})
	if err != nil {
		note(&res, "walk aborted: "+err.Error())
	}
	return res, err
}

func note(res *TreeResult, msg string) {
	if len(res.Errs) < 10 {
		res.Errs = append(res.Errs, msg)
	}
}

// sizeText renders a byte limit the way the skip notes say it.
func sizeText(n int64) string { return fmt.Sprintf("%d MiB", n>>20) }
