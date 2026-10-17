// Package dnssync keeps Cloudflare A and AAAA records in line with routes (DESIGN.md §7).
// A record ServanaGo created is "owned" and may be updated or deleted; one it merely adopted is never touched.
// Each name is dual-stack: an A record from the IPv4 target and, when an IPv6 target is set, an AAAA record
// from it. The two families are synced, adopted and reported independently.
package dnssync

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/store"
)

type Syncer struct {
	Host HostSpec // optional; see ReconcileHost
	cf   *cfdns.Client
	st   *store.Store
	now  func() time.Time
}

func New(cf *cfdns.Client, st *store.Store) *Syncer { return &Syncer{cf: cf, st: st, now: time.Now} }

// families is the order records are synced and listed in: A first.
var families = [...]string{store.FamilyA, store.FamilyAAAA}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Reconcile brings the site's A and AAAA records in line. Cloudflare failures are recorded on the
// dns_records rows (state "error") and are not returned: a DNS failure never reverts a site.
func (s *Syncer) Reconcile(ctx context.Context, siteID int64) error {
	return s.run(ctx, siteID, false)
}

// TakeOver overwrites conflicting records (of either family) and marks them owned.
func (s *Syncer) TakeOver(ctx context.Context, siteID int64) error { return s.run(ctx, siteID, true) }

func (s *Syncer) run(ctx context.Context, siteID int64, takeOver bool) error {
	rt, err := s.st.GetSite(ctx, siteID)
	if err != nil {
		return err
	}
	domains, err := s.st.ListDomains(ctx)
	if err != nil {
		return err
	}
	name := rt.Hostnames[0]
	dom, ok := store.ResolveDomain(domains, name)
	if !ok { // no domain, no zone: nothing to sync
		return nil
	}
	want := map[string]string{
		store.FamilyA:    first(rt.RecordIP, dom.DefaultIP),
		store.FamilyAAAA: first(rt.RecordIP6, dom.DefaultIP6),
	}
	for _, fam := range families {
		row, err := s.st.GetDNS(ctx, siteID, fam)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		has := err == nil
		row.SiteID, row.Family = siteID, fam
		next, drop := s.syncFamily(ctx, dom.ZoneID, name, fam, want[fam], row, has, takeOver)
		if drop {
			err = s.st.DeleteDNSRecord(ctx, siteID, fam)
		} else {
			err = s.st.UpsertDNS(ctx, next)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// syncFamily reconciles one name's record of one family. want == "" means no record of that family is
// wanted: an owned one is deleted, an adopted one is left alone, and either way the row is dropped (drop).
// A Cloudflare failure keeps the row and records state "error".
func (s *Syncer) syncFamily(ctx context.Context, zone, name, family, want string, row store.DNSRecord, has, takeOver bool) (next store.DNSRecord, drop bool) {
	row.Family = family
	if want == "" {
		if !has {
			return row, true
		}
		if row.Owned && row.CFRecordID != "" {
			if err := s.cf.DeleteRecord(ctx, zone, row.CFRecordID); err != nil {
				row.State, row.Error = "error", err.Error()
				return row, false
			}
		}
		return row, true
	}
	next, err := s.step(ctx, zone, name, family, want, row, takeOver)
	if err != nil {
		next = row
		next.State, next.Error = "error", err.Error()
	}
	next.Family = family
	return next, false
}

func (s *Syncer) step(ctx context.Context, zone, name, family, want string, row store.DNSRecord, takeOver bool) (store.DNSRecord, error) {
	found, err := s.cf.FindRecord(ctx, zone, name, family)
	if err != nil {
		return row, err
	}
	synced := func(id string, owned bool) store.DNSRecord {
		return store.DNSRecord{SiteID: row.SiteID, Family: family, CFRecordID: id, Content: want, Owned: owned, State: "synced",
			SyncedAt: s.now().UTC().Format(time.RFC3339)}
	}
	switch {
	case found == nil:
		id, err := s.cf.CreateRecord(ctx, zone, name, family, want)
		if err != nil {
			return row, err
		}
		return synced(id, true), nil
	case row.Owned && row.CFRecordID == found.ID, takeOver:
		if found.Content != want {
			if err := s.cf.UpdateRecord(ctx, zone, found.ID, name, family, want); err != nil {
				return row, err
			}
		}
		return synced(found.ID, true), nil
	case found.Content == want:
		return synced(found.ID, false), nil // adopt
	default:
		return store.DNSRecord{SiteID: row.SiteID, Family: family, CFRecordID: found.ID, Content: found.Content, State: "conflict",
			Error: fmt.Sprintf("%s already points to %s, not %s", name, found.Content, want)}, nil
	}
}

// Remove deletes the record if ServanaGo owns it and reports whether it did.
func (s *Syncer) Remove(ctx context.Context, zoneID string, rec store.DNSRecord) (bool, error) {
	if !rec.Owned || rec.CFRecordID == "" {
		return false, nil
	}
	if err := s.cf.DeleteRecord(ctx, zoneID, rec.CFRecordID); err != nil {
		return false, err
	}
	return true, nil
}

// HostSpec describes the records for SERVANAGO_HOST itself. A zero Name disables them; an empty IP6
// means no AAAA record.
type HostSpec struct{ Name, IP, IP6, Zone string }

// ReconcileHost syncs the UI host's A (and optional AAAA) record with the same owned/adopt/conflict rules
// as routes. Failures (including an unresolvable zone) are recorded as state "error", never returned.
func (s *Syncer) ReconcileHost(ctx context.Context, takeOver bool) error {
	if s.Host.Name == "" {
		return nil
	}
	zone, _, zerr := s.cf.ZoneFor(ctx, s.Host.Name, s.Host.Zone)
	if zerr != nil && s.Host.Zone == "" {
		zerr = fmt.Errorf("%w; set SERVANAGO_HOST_ZONE to the zone name", zerr)
	}
	want := map[string]string{store.FamilyA: s.Host.IP, store.FamilyAAAA: s.Host.IP6}
	for _, fam := range families {
		row, err := s.st.GetUIDNS(ctx, fam)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		has := err == nil
		row.Family = fam
		var next store.DNSRecord
		drop := false
		switch {
		case zerr != nil && want[fam] == "":
			continue // nothing wanted and nothing can be deleted without the zone
		case zerr != nil:
			next = row
			next.State, next.Error = "error", zerr.Error()
		default:
			next, drop = s.syncFamily(ctx, zone, s.Host.Name, fam, want[fam], row, has, takeOver)
		}
		if drop {
			err = s.st.DeleteUIDNS(ctx, fam)
		} else {
			err = s.st.UpsertUIDNS(ctx, next)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
