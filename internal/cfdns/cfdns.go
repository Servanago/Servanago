// Package cfdns wraps cloudflare-go for zone lookup and A-record management.
package cfdns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	return "", "", fmt.Errorf("%w for %s (tried %s)", ErrNoZone, host, strings.Join(tried, ", "))
}

// ErrNoZone means no visible zone encloses the hostname. The hostname is then served without a domain
// (HTTP-01, no DNS sync); any other ZoneFor error is a real failure.
var ErrNoZone = errors.New("no Cloudflare zone found")

// VerifyToken checks the API token is valid and active. /user/tokens/verify answers 401 for
// account-owned tokens, so on a 401 the token is accepted if it can list zones.
func (c *Client) VerifyToken(ctx context.Context) error {
	res, err := c.api.User.Tokens.Verify(ctx)
	if err != nil {
		var apiErr *cloudflare.Error
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
			if _, zerr := c.api.Zones.List(ctx, zones.ZoneListParams{PerPage: cloudflare.F(1.0)}); zerr == nil {
				return nil
			}
		}
		return fmt.Errorf("verify Cloudflare token: %w", err)
	}
	if res.Status != "active" {
		return fmt.Errorf("Cloudflare token status is %q, not active", res.Status)
	}
	return nil
}

// Record is the subset of a Cloudflare address record ServanaGo cares about.
type Record struct{ ID, Name, Content string }

const managedComment = "managed by servanago"

// Record families ServanaGo manages: A (IPv4) and AAAA (IPv6).
const (
	FamilyA    = "A"
	FamilyAAAA = "AAAA"
)

func checkFamily(family string) error {
	if family != FamilyA && family != FamilyAAAA {
		return fmt.Errorf("unsupported record family %q (want A or AAAA)", family)
	}
	return nil
}

// FindRecord returns the record of the given family (A or AAAA) named name, or nil if there is none.
func (c *Client) FindRecord(ctx context.Context, zoneID, name, family string) (*Record, error) {
	if err := checkFamily(family); err != nil {
		return nil, err
	}
	listType := dns.RecordListParamsTypeA
	if family == FamilyAAAA {
		listType = dns.RecordListParamsTypeAAAA
	}
	page, err := c.api.DNS.Records.List(ctx, dns.RecordListParams{
		ZoneID: cloudflare.F(zoneID),
		Type:   cloudflare.F(listType),
		Name:   cloudflare.F(dns.RecordListParamsName{Exact: cloudflare.F(name)}),
	})
	if err != nil {
		return nil, fmt.Errorf("list %s records for %s: %w", family, name, err)
	}
	var found *Record
	for _, r := range page.Result {
		if !strings.EqualFold(r.Name, name) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("multiple %s records named %s; resolve in Cloudflare first", family, name)
		}
		found = &Record{ID: r.ID, Name: r.Name, Content: r.Content}
	}
	return found, nil
}

// recordParam is satisfied by the SDK's A and AAAA record params, for both create and update calls.
type recordParam interface {
	dns.RecordNewParamsBodyUnion
	dns.RecordUpdateParamsBodyUnion
}

// recordBody is the DNS-only record body for the family.
func recordBody(name, family, ip string) recordParam {
	if family == FamilyAAAA {
		return dns.AAAARecordParam{
			Name: cloudflare.F(name), Content: cloudflare.F(ip), Type: cloudflare.F(dns.AAAARecordTypeAAAA),
			TTL: cloudflare.F(dns.TTL1), Proxied: cloudflare.F(false), Comment: cloudflare.F(managedComment),
		}
	}
	return dns.ARecordParam{
		Name: cloudflare.F(name), Content: cloudflare.F(ip), Type: cloudflare.F(dns.ARecordTypeA),
		TTL: cloudflare.F(dns.TTL1), Proxied: cloudflare.F(false), Comment: cloudflare.F(managedComment),
	}
}

// CreateRecord creates a DNS-only A or AAAA record and returns its id.
func (c *Client) CreateRecord(ctx context.Context, zoneID, name, family, ip string) (string, error) {
	if err := checkFamily(family); err != nil {
		return "", err
	}
	r, err := c.api.DNS.Records.New(ctx, dns.RecordNewParams{ZoneID: cloudflare.F(zoneID), Body: recordBody(name, family, ip)})
	if err != nil {
		return "", fmt.Errorf("create %s record %s: %w", family, name, err)
	}
	return r.ID, nil
}

// UpdateRecord points an existing record of the family at ip (and makes it DNS-only).
func (c *Client) UpdateRecord(ctx context.Context, zoneID, id, name, family, ip string) error {
	if err := checkFamily(family); err != nil {
		return err
	}
	if _, err := c.api.DNS.Records.Update(ctx, id, dns.RecordUpdateParams{ZoneID: cloudflare.F(zoneID), Body: recordBody(name, family, ip)}); err != nil {
		return fmt.Errorf("update %s record %s: %w", family, name, err)
	}
	return nil
}

func (c *Client) DeleteRecord(ctx context.Context, zoneID, id string) error {
	if _, err := c.api.DNS.Records.Delete(ctx, id, dns.RecordDeleteParams{ZoneID: cloudflare.F(zoneID)}); err != nil {
		return fmt.Errorf("delete DNS record %s: %w", id, err)
	}
	return nil
}
