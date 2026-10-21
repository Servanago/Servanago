package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// slugBase turns a hostname's first label into ^[a-z][a-z0-9-]{1,31}$ material: other characters become '-',
// a leading digit or a too-short label gets an "s-" prefix.
func slugBase(host string) string {
	label, _, _ := strings.Cut(strings.ToLower(host), ".")
	var b strings.Builder
	for _, c := range label {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) < 2 || slug[0] < 'a' || slug[0] > 'z' {
		slug = "s-" + slug
	}
	if len(slug) > 32 {
		slug = strings.TrimRight(slug[:32], "-")
	}
	return slug
}

// reservedSlugs belong to the PHP build job (user sg-phpbuild, units servanago-phpbuild and servanago-phpfetch).
var reservedSlugs = map[string]bool{"phpbuild": true, "phpfetch": true}

// newSlug returns slugBase(host), or that with -2, -3, ... appended until no site has it.
func (s *Store) newSlug(ctx context.Context, host string) (string, error) {
	base := slugBase(host)
	for n := 1; ; n++ {
		slug := base
		if n > 1 {
			suffix := "-" + strconv.Itoa(n)
			slug = strings.TrimRight(base[:min(len(base), 32-len(suffix))], "-") + suffix
		}
		var taken int
		if reservedSlugs[slug] {
			taken = 1
		} else if err := s.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sites WHERE slug=?`, slug).Scan(&taken); err != nil {
			return "", fmt.Errorf("check slug %s: %w", slug, err)
		}
		if taken == 0 {
			return slug, nil
		}
	}
}
