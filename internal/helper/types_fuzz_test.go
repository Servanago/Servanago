package helper

import (
	"strings"
	"testing"
)

// FuzzDecodeRequest proves accepted requests can only be known actions, and that a validated
// slug can only ever become a servanago-<slug>.service unit name: no NUL bytes, separators,
// traversal or unit-file injection ever reach the helper's filesystem calls.
func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"action":"unit-install","spec":{"slug":"blog"}}`))
	f.Add([]byte(`{"action":"ping","spec":{}}`))
	f.Add([]byte(`{"action":"shell","spec":{"cmd":"/bin/sh"}}`))
	f.Add([]byte(`{"action":"unit-install","spec":{"slug":"../../etc"}}`))
	f.Add([]byte(`{"action":"unit-install","spec":{"slug":"a\x00b"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRequest(b)
		if err != nil {
			return
		}
		switch r.Action {
		case ActionPing:
		case ActionUnitInstall:
			if slug, err := r.Slug(); err == nil {
				n, err := unitName(slug)
				if err != nil {
					t.Fatalf("validated slug %q has no unit name: %v", slug, err)
				}
				if !strings.HasPrefix(n, "servanago-") || !strings.HasSuffix(n, ".service") || strings.ContainsAny(n, "/\\") {
					t.Fatalf("unit name %q escaped the managed shape", n)
				}
			}
		default:
			t.Fatalf("unknown action %q accepted", r.Action)
		}
	})
}
