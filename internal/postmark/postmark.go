// Package postmark sends one plain-text email through the Postmark HTTP API with a server token.
package postmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// endpoint is a var so tests can point it at an httptest server.
var endpoint = "https://api.postmarkapp.com/email"

var client = &http.Client{Timeout: 15 * time.Second}

type Client struct{ Token string }

// Send matches the gate's Mailer contract. The token never appears in an error.
func (c Client) Send(from, to, subject, body string) error {
	if c.Token == "" {
		return fmt.Errorf("Postmark server token is not set")
	}
	b, err := json.Marshal(map[string]string{"From": from, "To": to, "Subject": subject, "TextBody": body, "MessageStream": "outbound"})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", c.Token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("postmark request: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		ErrorCode int
		Message   string
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || out.ErrorCode != 0 {
		return fmt.Errorf("postmark: status %d, code %d: %s", resp.StatusCode, out.ErrorCode, out.Message)
	}
	return nil
}
