package config

import (
	"fmt"
	"regexp"
)

var snippetNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,39}$`)

// ValidateSnippetName accepts a lowercase name of 2-40 characters: letters, digits, '_' and '-'.
func ValidateSnippetName(name string) error {
	if !snippetNameRE.MatchString(name) {
		return fmt.Errorf("snippet name %q: 2-40 characters, lowercase letters, digits, '_' and '-', starting with a letter", name)
	}
	return nil
}
