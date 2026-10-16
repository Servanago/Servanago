package web

import (
	"strings"

	"github.com/servanago/servanago/internal/store"
)

// stateRank orders record states by how much attention they need.
var stateRank = map[string]int{"synced": 0, "pending": 1, "conflict": 2, "error": 3}

// worstState is the state needing the most attention among rows, or "" when there are none.
func worstState(rows []store.DNSRecord) string {
	worst := ""
	for _, r := range rows {
		if worst == "" || stateRank[r.State] > stateRank[worst] {
			worst = r.State
		}
	}
	return worst
}

// ownedRecords are the rows ServanaGo created in Cloudflare: the only ones it may delete.
func ownedRecords(rows []store.DNSRecord) []store.DNSRecord {
	var out []store.DNSRecord
	for _, r := range rows {
		if r.Owned && r.CFRecordID != "" {
			out = append(out, r)
		}
	}
	return out
}

// recordSummary renders rows as "A 10.0.0.1, AAAA 2001:db8::1", or just the address when there is one record.
func recordSummary(rows []store.DNSRecord) string {
	if len(rows) == 1 {
		return rows[0].Content
	}
	parts := make([]string, len(rows))
	for i, r := range rows {
		parts[i] = r.Family + " " + r.Content
	}
	return strings.Join(parts, ", ")
}
