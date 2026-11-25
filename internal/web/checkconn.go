package web

import (
	"context"
	"crypto/tls"
	"html"
	"net"
	"time"
)

func htmlEscape(s string) string { return html.EscapeString(s) }

func splitAddr(a string) (host, port string, err error) { return net.SplitHostPort(a) }

type netResolver struct{}

func (netResolver) lookup(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func tlsHandshake(ctx context.Context, host, port string, skip bool) error {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	defer conn.Close()
	c := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: skip}) // #nosec G402: the admin's explicit skip-verify choice, probe only
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	return c.HandshakeContext(ctx)
}
