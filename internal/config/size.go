package config

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxBodyLimit is the largest upload limit a route may set.
const MaxBodyLimit = 100 << 30

var sizeUnits = []struct {
	suffix string
	mult   int64
}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}}

// ParseSize reads "2GB", "512MB", "100KB" or a plain byte count; the result is 1..MaxBodyLimit bytes.
func ParseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range sizeUnits {
		if strings.HasSuffix(t, u.suffix) {
			t, mult = strings.TrimSpace(strings.TrimSuffix(t, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 1 || n > MaxBodyLimit/mult {
		return 0, fmt.Errorf("%q is not a size between 1 byte and 100GB (examples: 512MB, 2GB)", s)
	}
	return n * mult, nil
}

// FormatSize is ParseSize's inverse: the largest unit that divides evenly; "" for 0.
func FormatSize(n int64) string {
	for _, u := range sizeUnits {
		if n > 0 && n%u.mult == 0 {
			return strconv.FormatInt(n/u.mult, 10) + u.suffix
		}
	}
	if n == 0 {
		return ""
	}
	return strconv.FormatInt(n, 10)
}
