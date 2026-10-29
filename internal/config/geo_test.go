package config

import (
	"slices"
	"strings"
	"testing"
)

func TestValidateCountryList(t *testing.T) {
	codes, err := ValidateCountryList("de, US  us")
	if err != nil || !slices.Equal(codes, []string{"DE", "US"}) {
		t.Fatalf("codes: %v %v", codes, err)
	}
	if _, err := ValidateCountryList(""); err == nil {
		t.Error("an empty list was accepted")
	}
	if _, err := ValidateCountryList("USA"); err == nil || !strings.Contains(err.Error(), "ISO 3166-1") {
		t.Errorf("wrong shape accepted: %v", err)
	}
}
