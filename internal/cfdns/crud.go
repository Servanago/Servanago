// Admin DNS CRUD on top of the same Cloudflare token dnssync uses. Everything here is
// read/verified against Cloudflare live; ServanaGo keeps no second copy of the records.
package cfdns

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/zones"
)

// crudTypes are the types create/update accepts. Every other type Cloudflare knows is listed
// read-only (TLSA, DS, SVCB, …): adding one is one branch in each builder, on demand.
var crudTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true,
	"MX": true, "SRV": true, "CAA": true, "NS": true,
}

// proxyable are the types Cloudflare lets carry the proxied flag; for the others the flag
// is left off the request instead of sent as false, which the API does not accept.
var proxyable = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

func checkCrudType(t string) error {
	if !crudTypes[t] {
		return fmt.Errorf("record type %q is read-only in ServanaGo", t)
	}
	return nil
}

// Zone is one token-visible DNS zone of the admin DNS page.
type Zone struct{ ID, Name, Status string }

// ListZones returns every zone the token can see, sorted by name.
func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	var out []Zone
	it := c.api.Zones.ListAutoPaging(ctx, zones.ZoneListParams{PerPage: cloudflare.F(50.0)})
	for it.Next() {
		z := it.Current()
		out = append(out, Zone{ID: z.ID, Name: z.Name, Status: string(z.Status)})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	slices.SortFunc(out, func(a, b Zone) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// FullRecord is one DNS record as the admin CRUD surfaces it. SRV and CAA records keep their
// structured data as a single content string ("10 5 8080 app" / `0 issue "letsencrypt.org"`),
// which maps to and from Cloudflare's data object here.
type FullRecord struct {
	ID       string
	Name     string
	Type     string
	Content  string
	TTL      int // 1 = Auto
	Proxied  bool
	Comment  string
	Priority int // MX/SRV priority; 0 for the other types
}

func ttlOf(r FullRecord) dns.TTL {
	if r.TTL <= 0 {
		return 1
	}
	return dns.TTL(r.TTL)
}

// srvContent renders Cloudflare's SRV data as the one-line form the UI edits. The SDK decodes
// the data object as SRVRecordData; a raw map (other clients' shapes) still works.
func srvContent(data any) string {
	switch d := data.(type) {
	case dns.SRVRecordData:
		return fmt.Sprintf("%v %v %v %v", d.Priority, d.Weight, d.Port, d.Target)
	case map[string]any:
		return fmt.Sprintf("%v %v %v %v", d["priority"], d["weight"], d["port"], d["target"])
	default:
		return ""
	}
}

// caaContent renders Cloudflare's CAA data the same way.
func caaContent(data any) string {
	switch d := data.(type) {
	case dns.CAARecordData:
		return fmt.Sprintf("%v %s %q", d.Flags, d.Tag, d.Value)
	case map[string]any:
		return fmt.Sprintf("%v %s %q", d["flags"], d["tag"], d["value"])
	default:
		return ""
	}
}

func srvData(content string) (map[string]any, error) {
	f := strings.Fields(content)
	if len(f) != 4 {
		return nil, fmt.Errorf("SRV content must be \"priority weight port target\", got %q", content)
	}
	pri, err := strconv.Atoi(f[0])
	if err != nil {
		return nil, fmt.Errorf("SRV priority: %w", err)
	}
	weight, err := strconv.Atoi(f[1])
	if err != nil {
		return nil, fmt.Errorf("SRV weight: %w", err)
	}
	port, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, fmt.Errorf("SRV port: %w", err)
	}
	return map[string]any{"priority": pri, "weight": weight, "port": port, "target": f[3]}, nil
}

func caaData(content string) (map[string]any, error) {
	f := strings.Fields(content)
	if len(f) != 2 && len(f) != 3 {
		return nil, fmt.Errorf("CAA content must be \"flags tag [value]\", got %q", content)
	}
	flags, err := strconv.Atoi(f[0])
	if err != nil {
		return nil, fmt.Errorf("CAA flags: %w", err)
	}
	return map[string]any{"flags": flags, "tag": f[1], "value": strings.Trim(strings.Join(f[2:], " "), `"`)}, nil
}

// ListRecords returns a zone's records of every type, sorted by type then name. The raw JSON is
// decoded here instead of the SDK's typed RecordResponse: its union decode loses the priority
// and data fields (probed against v7.13.0), and one envelope beats unwrapping eight record types.
type dnsRecordsEnvelope struct {
	Result []struct {
		ID, Name, Type, Content, Comment string
		Proxied                          bool
		TTL                              int
		Priority                         int
		Data                             map[string]any
	} `json:"result"`
}

const recordsPerPage = 100.0

func (c *Client) ListRecords(ctx context.Context, zoneID string) ([]FullRecord, error) {
	var out []FullRecord
	for page := 1; ; page++ {
		env := dnsRecordsEnvelope{} // fresh each page: a reused struct would merge stale fields
		_, err := c.api.DNS.Records.List(ctx, dns.RecordListParams{
			ZoneID:  cloudflare.F(zoneID),
			Page:    cloudflare.F(float64(page)),
			PerPage: cloudflare.F(recordsPerPage),
		}, option.WithResponseBodyInto(&env))
		if err != nil {
			return nil, fmt.Errorf("list DNS records: %w", err)
		}
		for _, r := range env.Result {
			fr := FullRecord{ID: r.ID, Name: r.Name, Type: r.Type, TTL: r.TTL, Proxied: r.Proxied,
				Comment: r.Comment, Priority: r.Priority, Content: r.Content}
			switch fr.Type {
			case "SRV":
				if fr.Content = srvContent(r.Data); fr.Content == "" {
					fr.Content = r.Content
				}
			case "CAA":
				if fr.Content = caaContent(r.Data); fr.Content == "" {
					fr.Content = r.Content
				}
			}
			out = append(out, fr)
		}
		if len(env.Result) < int(recordsPerPage) {
			break
		}
	}
	slices.SortFunc(out, func(a, b FullRecord) int {
		if c := strings.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

func newBody(r FullRecord, content string, data any) dns.RecordNewParamsBody {
	b := dns.RecordNewParamsBody{
		Name:    cloudflare.F(r.Name),
		Type:    cloudflare.F(dns.RecordNewParamsBodyType(r.Type)),
		TTL:     cloudflare.F(ttlOf(r)),
		Comment: cloudflare.F(r.Comment),
	}
	switch {
	case data != nil:
		b.Data = cloudflare.F(data)
	default:
		b.Content = cloudflare.F(content)
	}
	if r.Priority != 0 {
		b.Priority = cloudflare.F(float64(r.Priority))
	}
	if proxyable[r.Type] {
		b.Proxied = cloudflare.F(r.Proxied)
	}
	return b
}

func updateBody(r FullRecord, content string, data any) dns.RecordUpdateParamsBody {
	b := dns.RecordUpdateParamsBody{
		Name:    cloudflare.F(r.Name),
		Type:    cloudflare.F(dns.RecordUpdateParamsBodyType(r.Type)),
		TTL:     cloudflare.F(ttlOf(r)),
		Comment: cloudflare.F(r.Comment),
	}
	switch {
	case data != nil:
		b.Data = cloudflare.F(data)
	default:
		b.Content = cloudflare.F(content)
	}
	if r.Priority != 0 {
		b.Priority = cloudflare.F(float64(r.Priority))
	}
	if proxyable[r.Type] {
		b.Proxied = cloudflare.F(r.Proxied)
	}
	return b
}

// CreateRecordFull creates a record of any crudType in the zone and returns its id.
func (c *Client) CreateRecordFull(ctx context.Context, zoneID string, r FullRecord) (string, error) {
	if err := checkCrudType(r.Type); err != nil {
		return "", err
	}
	content, data, err := recordPayload(r)
	if err != nil {
		return "", err
	}
	res, err := c.api.DNS.Records.New(ctx, dns.RecordNewParams{ZoneID: cloudflare.F(zoneID), Body: newBody(r, content, data)})
	if err != nil {
		return "", fmt.Errorf("create %s record %s: %w", r.Type, r.Name, err)
	}
	return res.ID, nil
}

func recordPayload(r FullRecord) (content string, data any, err error) {
	switch r.Type {
	case "SRV":
		data, err = srvData(r.Content)
		return "", data, err
	case "CAA":
		data, err = caaData(r.Content)
		return "", data, err
	default:
		return r.Content, nil, nil
	}
}

// UpdateRecordFull rewrites a record of any crudType.
func (c *Client) UpdateRecordFull(ctx context.Context, zoneID, id string, r FullRecord) error {
	if err := checkCrudType(r.Type); err != nil {
		return err
	}
	content, data, err := recordPayload(r)
	if err != nil {
		return err
	}
	if _, err := c.api.DNS.Records.Update(ctx, id, dns.RecordUpdateParams{ZoneID: cloudflare.F(zoneID), Body: updateBody(r, content, data)}); err != nil {
		return fmt.Errorf("update %s record %s: %w", r.Type, r.Name, err)
	}
	return nil
}

// (Deletion takes DeleteRecord from cfdns.go: a delete has no per-type payload to convert.)
