package store

import (
	"context"
	"strconv"
	"testing"
)

func TestAuditNewestFirstAndCapped(t *testing.T) {
	s, ctx := open(t), context.Background()
	if rows, err := s.ListAudit(ctx, 10); err != nil || len(rows) != 0 {
		t.Fatalf("empty: %v %v", rows, err)
	}
	if err := s.AddAudit(ctx, AuditEntry{At: "2026-10-17T10:00:00Z", Actor: "alice", Action: "site.created", Target: "a.example.com", IP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAudit(ctx, AuditEntry{At: "2026-10-17T10:01:00Z", Actor: "bob", Action: "user.added", Target: "carol"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListAudit(ctx, 10)
	if len(rows) != 2 || rows[0].Actor != "bob" || rows[1].Actor != "alice" || rows[1].IP != "10.0.0.1" || rows[0].Target != "carol" {
		t.Fatalf("order and fields: %+v", rows)
	}
	if rows, _ = s.ListAudit(ctx, 1); len(rows) != 1 || rows[0].Actor != "bob" {
		t.Fatalf("limit: %+v", rows)
	}

	// The table keeps only the newest AuditCap rows.
	for i := range AuditCap + 25 {
		if err := s.AddAudit(ctx, AuditEntry{At: "2026-10-17T11:00:00Z", Actor: "x", Action: "n", Target: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil || n != AuditCap {
		t.Fatalf("rows kept: %d %v (want %d)", n, err, AuditCap)
	}
	rows, _ = s.ListAudit(ctx, 1)
	if rows[0].Target != strconv.Itoa(AuditCap+24) {
		t.Errorf("the newest row was trimmed: %+v", rows[0])
	}
}
