// Package dnssync keeps Cloudflare A records in line with routes (DESIGN.md §7).
// A record Caretakarr created is "owned" and may be updated or deleted; one it merely adopted is never touched.
package dnssync

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/caretakarr/caretakarr/internal/cfdns"
	"github.com/caretakarr/caretakarr/internal/store"
)

type Syncer struct {
	Host HostSpec // optional; see ReconcileHost
	cf   *cfdns.Client
	st   *store.Store
	now  func() time.Time
}

func New(cf *cfdns.Client, st *store.Store) *Syncer { return &Syncer{cf: cf, st: st, now: time.Now} }

// Reconcile brings the route's A record in line. Cloudflare failures are recorded on the
// dns_records row (state "error") and are not returned: a DNS failure never reverts a route.
func (s *Syncer) Reconcile(ctx context.Context, routeID int64) error {
	return s.run(ctx, routeID, false)
}

// TakeOver overwrites a conflicting record and marks it owned.
func (s *Syncer) TakeOver(ctx context.Context, routeID int64) error { return s.run(ctx, routeID, true) }

func (s *Syncer) run(ctx context.Context, routeID int64, takeOver bool) error {
	rt, err := s.st.GetRoute(ctx, routeID)
	if err != nil {
		return err
	}
	dom, err := s.st.GetDomain(ctx, rt.DomainID)
	if err != nil {
		return err
	}
	row, err := s.st.GetDNS(ctx, routeID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	row.RouteID = routeID
	want := rt.RecordIP
	if want == "" {
		want = dom.DefaultIP
	}
	next, err := s.step(ctx, dom.ZoneID, rt.Subdomain+"."+dom.Name, want, row, takeOver)
	if err != nil {
		next = row
		next.State, next.Error = "error", err.Error()
	}
	return s.st.UpsertDNS(ctx, next)
}

func (s *Syncer) step(ctx context.Context, zone, name, want string, row store.DNSRecord, takeOver bool) (store.DNSRecord, error) {
	found, err := s.cf.FindA(ctx, zone, name)
	if err != nil {
		return row, err
	}
	synced := func(id string, owned bool) store.DNSRecord {
		return store.DNSRecord{RouteID: row.RouteID, CFRecordID: id, Content: want, Owned: owned, State: "synced",
			SyncedAt: s.now().UTC().Format(time.RFC3339)}
	}
	switch {
	case found == nil:
		id, err := s.cf.CreateA(ctx, zone, name, want)
		if err != nil {
			return row, err
		}
		return synced(id, true), nil
	case row.Owned && row.CFRecordID == found.ID, takeOver:
		if found.Content != want {
			if err := s.cf.UpdateA(ctx, zone, found.ID, name, want); err != nil {
				return row, err
			}
		}
		return synced(found.ID, true), nil
	case found.Content == want:
		return synced(found.ID, false), nil // adopt
	default:
		return store.DNSRecord{RouteID: row.RouteID, CFRecordID: found.ID, Content: found.Content, State: "conflict",
			Error: fmt.Sprintf("%s already points to %s, not %s", name, found.Content, want)}, nil
	}
}

// Remove deletes the record if Caretakarr owns it and reports whether it did.
func (s *Syncer) Remove(ctx context.Context, zoneID string, rec store.DNSRecord) (bool, error) {
	if !rec.Owned || rec.CFRecordID == "" {
		return false, nil
	}
	if err := s.cf.DeleteRecord(ctx, zoneID, rec.CFRecordID); err != nil {
		return false, err
	}
	return true, nil
}

// HostSpec describes the record for CARETAKARR_HOST itself. A zero Name disables it.
type HostSpec struct{ Name, IP, Zone string }

// ReconcileHost syncs the UI host's A record with the same owned/adopt/conflict rules as routes.
// Failures (including an unresolvable zone) are recorded as state "error", never returned.
func (s *Syncer) ReconcileHost(ctx context.Context, takeOver bool) error {
	if s.Host.Name == "" {
		return nil
	}
	row, err := s.st.GetUIDNS(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	zone, _, err := s.cf.ZoneFor(ctx, s.Host.Name, s.Host.Zone)
	var next store.DNSRecord
	if err == nil {
		next, err = s.step(ctx, zone, s.Host.Name, s.Host.IP, row, takeOver)
	}
	if err != nil {
		next = row
		next.State, next.Error = "error", err.Error()
	}
	return s.st.UpsertUIDNS(ctx, next)
}
