// Country rule lists: the site form and the panel's settings share one parser.
package config

import (
	"fmt"
	"regexp"
	"strings"
)

// countryRE matches an ISO 3166-1 alpha-2 code; a wrong code simply never matches a database
// entry, so only the shape is validated here.
var countryRE = regexp.MustCompile(`^[A-Z]{2}$`)

// ValidateCountryList normalizes a space-, comma- or newline-separated country list. The list
// must be non-empty: an empty list under a rule says nothing and is refused as a user error.
func ValidateCountryList(s string) ([]string, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' || r == ';' })
	if len(fields) == 0 {
		return nil, fmt.Errorf("a country rule needs at least one code, such as DE or US")
	}
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.ToUpper(strings.TrimSpace(f))
		if !countryRE.MatchString(f) {
			return nil, fmt.Errorf("%q is not an ISO 3166-1 two-letter country code (like DE or US)", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}
