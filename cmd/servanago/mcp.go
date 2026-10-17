package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runMCP implements `servanago mcp`: a stdio MCP server for clients that cannot speak HTTP. It holds no logic of its
// own; it relays every message to the /mcp endpoint of a running instance (SERVANAGO_MCP_URL, default the local UI
// listener), which owns the apply path and the token check.
func runMCP() error {
	token := os.Getenv("SERVANAGO_MCP_TOKEN")
	if token == "" {
		return errors.New("SERVANAGO_MCP_TOKEN is not set")
	}
	url := os.Getenv("SERVANAGO_MCP_URL")
	if url == "" {
		url = "http://" + strings.TrimSpace(envOr("UI_LISTEN", "127.0.0.1:8080")) + "/mcp"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	remote := &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: bearer{token}}}
	return relay(ctx, &mcp.StdioTransport{}, remote)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// bearer adds the token to every request, including the SSE reads of a long call.
type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// relay copies JSON-RPC messages both ways until either side closes.
func relay(ctx context.Context, a, b mcp.Transport) error {
	ca, err := a.Connect(ctx)
	if err != nil {
		return fmt.Errorf("connect stdio: %w", err)
	}
	cb, err := b.Connect(ctx)
	if err != nil {
		_ = ca.Close()
		return fmt.Errorf("connect %T: %w", b, err)
	}
	pump := func(from, to mcp.Connection) error {
		for {
			m, err := from.Read(ctx)
			if err != nil {
				return err
			}
			if err := to.Write(ctx, m); err != nil {
				return err
			}
		}
	}
	errc := make(chan error, 2)
	go func() { errc <- pump(ca, cb) }()
	go func() { errc <- pump(cb, ca) }()
	err = <-errc
	_ = ca.Close()
	_ = cb.Close()
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
