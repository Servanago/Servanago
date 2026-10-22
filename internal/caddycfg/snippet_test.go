package caddycfg

import (
	"encoding/json"
	"strings"
	"testing"
)

const blockSensitive = `@dot path_regexp dot ^(?:|/)\.[^/]+(?:/.*)?$
@lock path /composer.json /composer.lock /package.json /go.sum
respond @dot 404
respond @lock 404`

func TestAdaptSnippet(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{ // want = "" means accepted
		{"block", blockSensitive, ""},
		{"encode", "encode gzip zstd", ""},
		{"header", "header X-Frame-Options DENY", ""},
		{"empty", "  \n", "empty"},
		{"proxy", "reverse_proxy 127.0.0.1:9", "reverse_proxy"},
		{"files", "file_server", "file_server"},
		{"root", "root * /etc", `"vars"`},
		{"basic", "basic_auth {\n\ta b\n}", "authentication"},
		{"import", "import /etc/passwd", "import"},
		{"file placeholder", `respond "{file./etc/passwd}"`, "{file."},
		{"env placeholder", `respond "{env.HOME}"`, "{env."},
		{"env at parse", `respond "{$HOME}"`, "{$"},
		{"site injection", "}\n:443 {\nreverse_proxy 127.0.0.1:9", "one site"},
		{"tls does nothing here", "tls {\n\tdns cloudflare x\n}", "no effect"},
		{"log does nothing here", "log {\n\toutput stdout\n}", "no effect"},
		{"too big", strings.Repeat("# x\n", 5000), "too long"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, err := AdaptSnippet(tc.body)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.want == "" && len(routes) == 0:
				t.Fatal("no routes")
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// The adapted routes must be plain JSON the renderer can embed.
func TestAdaptSnippetShape(t *testing.T) {
	routes, err := AdaptSnippet("encode gzip zstd")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(routes)
	if !strings.Contains(string(b), `"handler":"encode"`) {
		t.Fatalf("routes = %s", b)
	}
}
