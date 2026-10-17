package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client is the unprivileged side: the control plane sends one typed action to the helper and
// reads one reply. Spec fields are validated by the helper, but never constructed from
// untrusted strings by callers.
type Client struct {
	Socket string
}

func NewClient(socket string) *Client { return &Client{Socket: socket} }

func (c *Client) Call(ctx context.Context, action string, spec Spec) (Response, error) {
	sb, err := json.Marshal(spec) // a closed struct, never caller-controlled
	if err != nil {
		return Response{}, err
	}
	req := Request{Action: action, Spec: sb}
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return Response{}, fmt.Errorf("dial helper %s: %w", c.Socket, err)
	}
	defer conn.Close()
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return Response{}, fmt.Errorf("write helper: %w", err)
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return Response{}, fmt.Errorf("read helper reply: %w", err)
	}
	var resp Response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return Response{}, fmt.Errorf("parse helper reply: %w", err)
	}
	if !resp.OK && resp.Error != "" {
		return resp, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp, nil
}
