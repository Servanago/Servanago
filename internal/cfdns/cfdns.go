// Package cfdns wraps cloudflare-go for zone lookup and A-record management.
package cfdns

import (
	"context"
	"fmt"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/zones"
)

type Client struct{ api *cloudflare.Client }

// New builds a client; tests pass option.WithBaseURL to point it at httptest.
func New(token string, opts ...option.RequestOption) *Client {
	return &Client{api: cloudflare.NewClient(append([]option.RequestOption{option.WithAPIToken(token)}, opts...)...)}
}

// ZoneID resolves the Cloudflare zone for an exact domain name the token can see.
func (c *Client) ZoneID(ctx context.Context, name string) (string, error) {
	page, err := c.api.Zones.List(ctx, zones.ZoneListParams{Name: cloudflare.F(name)})
	if err != nil {
		return "", fmt.Errorf("look up zone %s: %w", name, err)
	}
	for _, z := range page.Result {
		if strings.EqualFold(z.Name, name) {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("zone %s not found: the token cannot see it (needs Zone:Read on that zone)", name)
}

// VerifyToken checks the API token is valid and active.
func (c *Client) VerifyToken(ctx context.Context) error {
	res, err := c.api.User.Tokens.Verify(ctx)
	if err != nil {
		return fmt.Errorf("verify Cloudflare token: %w", err)
	}
	if res.Status != "active" {
		return fmt.Errorf("Cloudflare token status is %q, not active", res.Status)
	}
	return nil
}
