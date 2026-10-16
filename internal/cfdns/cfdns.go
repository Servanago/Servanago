// Package cfdns wraps cloudflare-go for zone lookup and A-record management.
package cfdns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
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
	return "", fmt.Errorf("zone %s: %w (the token cannot see it; it needs Zone:Read on that zone)", name, ErrZoneNotFound)
}

// ErrZoneNotFound means the API answered but no visible zone has that name.
var ErrZoneNotFound = errors.New("not found")

// ZoneFor finds the zone holding host: override verbatim if set, else the closest enclosing zone,
// trying host, then each parent down to two labels. API errors abort the walk; only not-found continues it.
func (c *Client) ZoneFor(ctx context.Context, host, override string) (id, zone string, err error) {
	if override != "" {
		id, err = c.ZoneID(ctx, override)
		return id, override, err
	}
	var tried []string
	for name := host; strings.Count(name, ".") >= 1; {
		tried = append(tried, name)
		id, err := c.ZoneID(ctx, name)
		if err == nil {
			return id, name, nil
		}
		if !errors.Is(err, ErrZoneNotFound) {
			return "", "", err
		}
		_, name, _ = strings.Cut(name, ".")
	}
	return "", "", fmt.Errorf("no Cloudflare zone found for %s (tried %s)", host, strings.Join(tried, ", "))
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

// Record is the subset of a Cloudflare A record ServanaGo cares about.
type Record struct{ ID, Name, Content string }

const managedComment = "managed by servanago"

// FindA returns the A record named name, or nil if there is none.
func (c *Client) FindA(ctx context.Context, zoneID, name string) (*Record, error) {
	page, err := c.api.DNS.Records.List(ctx, dns.RecordListParams{
		ZoneID: cloudflare.F(zoneID),
		Type:   cloudflare.F(dns.RecordListParamsTypeA),
		Name:   cloudflare.F(dns.RecordListParamsName{Exact: cloudflare.F(name)}),
	})
	if err != nil {
		return nil, fmt.Errorf("list A records for %s: %w", name, err)
	}
	var found *Record
	for _, r := range page.Result {
		if !strings.EqualFold(r.Name, name) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("multiple A records named %s; resolve in Cloudflare first", name)
		}
		found = &Record{ID: r.ID, Name: r.Name, Content: r.Content}
	}
	return found, nil
}

func aRecord(name, ip string) dns.ARecordParam {
	return dns.ARecordParam{
		Name: cloudflare.F(name), Content: cloudflare.F(ip), Type: cloudflare.F(dns.ARecordTypeA),
		TTL: cloudflare.F(dns.TTL1), Proxied: cloudflare.F(false), Comment: cloudflare.F(managedComment),
	}
}

// CreateA creates a DNS-only A record and returns its id.
func (c *Client) CreateA(ctx context.Context, zoneID, name, ip string) (string, error) {
	r, err := c.api.DNS.Records.New(ctx, dns.RecordNewParams{ZoneID: cloudflare.F(zoneID), Body: aRecord(name, ip)})
	if err != nil {
		return "", fmt.Errorf("create A record %s: %w", name, err)
	}
	return r.ID, nil
}

// UpdateA points an existing record at ip (and makes it DNS-only).
func (c *Client) UpdateA(ctx context.Context, zoneID, id, name, ip string) error {
	if _, err := c.api.DNS.Records.Update(ctx, id, dns.RecordUpdateParams{ZoneID: cloudflare.F(zoneID), Body: aRecord(name, ip)}); err != nil {
		return fmt.Errorf("update A record %s: %w", name, err)
	}
	return nil
}

func (c *Client) DeleteRecord(ctx context.Context, zoneID, id string) error {
	if _, err := c.api.DNS.Records.Delete(ctx, id, dns.RecordDeleteParams{ZoneID: cloudflare.F(zoneID)}); err != nil {
		return fmt.Errorf("delete DNS record %s: %w", id, err)
	}
	return nil
}
