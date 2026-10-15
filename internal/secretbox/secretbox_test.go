package secretbox

import (
	"bytes"
	"strings"
	"testing"
)

const key = "0123456789abcdef0123456789abcdef"

func TestRoundTrip(t *testing.T) {
	blob, err := Seal(key, []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, blob)
	if err != nil || !bytes.Equal(got, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestOpenRejects(t *testing.T) {
	blob, _ := Seal(key, []byte("secret"))
	flipped := bytes.Clone(blob)
	flipped[len(flipped)-1] ^= 1
	for name, c := range map[string]struct {
		key  string
		blob []byte
	}{
		"wrong key":   {strings.ToUpper(key), blob},
		"flipped bit": {key, flipped},
		"short blob":  {key, blob[:5]},
		"empty blob":  {key, nil},
		"empty key":   {"", blob},
	} {
		if _, err := Open(c.key, c.blob); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestSealIsRandomised(t *testing.T) {
	a, _ := Seal(key, []byte("x"))
	b, _ := Seal(key, []byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("same nonce reused")
	}
}
