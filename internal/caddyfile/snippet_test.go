package caddyfile

import (
	"strings"
	"testing"
)

// A snippet with a multi-line named matcher is captured whole, and the sites that import it say so.
func TestParseSnippetWithMatcherBlock(t *testing.T) {
	src := `(block_sensitive) {
	@block {
		path /composer.json
		path /go.sum
	}

	respond @block 404
}

app.example.com {
	import block_sensitive
	reverse_proxy http://192.168.1.2:80
}
`
	sites, snippets, skipped := Parse(strings.NewReader(src))
	if len(skipped) != 0 || len(sites) != 1 || len(sites[0].Imports) != 1 || sites[0].Imports[0] != "block_sensitive" {
		t.Fatalf("sites %+v skipped %+v", sites, skipped)
	}
	want := "@block {\npath /composer.json\npath /go.sum\n}\nrespond @block 404"
	if len(snippets) != 1 || snippets[0].Name != "block_sensitive" || snippets[0].Body != want {
		t.Fatalf("snippets = %+v", snippets)
	}
}
