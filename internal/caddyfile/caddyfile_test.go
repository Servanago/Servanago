package caddyfile

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	src := `(cloudflare) {
	tls {
		dns cloudflare {$TOKEN}
	}
}

plain.example.com {
	import cloudflare
	reverse_proxy http://192.168.25.165:8766
}

secure.example.com {
	import cloudflare
	reverse_proxy https://192.168.25.226:443 {
		transport http {
			tls_insecure_skip_verify
		}
		header_up X-Forwarded-Port "443"
	}
	log {
		output stdout
	}
}

stream.example.com {
	import cloudflare
	reverse_proxy http://192.168.25.165:8788 {
		flush_interval -1
	}
	request_body {
		max_size 2GB
	}
}

timed.example.com {
	reverse_proxy http://192.168.25.165:1 {
		flush_interval 100ms
	}
	request_body {
		max_size 1GB
		other 1
	}
}

php.example.com {
	import cloudflare
	root * /var/www/x
	php_fastcgi php:9000
	file_server
}

dock.example.com {
	import cloudflare
	reverse_proxy http://host.docker.internal:1111
}
`
	sites, skipped := Parse(strings.NewReader(src))

	want := []Site{
		{Hostname: "plain.example.com", Scheme: "http", Host: "192.168.25.165", Port: 8766},
		{Hostname: "secure.example.com", Scheme: "https", Host: "192.168.25.226", Port: 443, SkipVerify: true,
			Dropped: []string{"header_up", "log"}},
		{Hostname: "stream.example.com", Scheme: "http", Host: "192.168.25.165", Port: 8788, Stream: true, MaxBody: "2GB"},
		{Hostname: "timed.example.com", Scheme: "http", Host: "192.168.25.165", Port: 1, MaxBody: "1GB",
			Dropped: []string{"flush_interval", "request_body"}},
		{Hostname: "dock.example.com", Scheme: "http", Host: "host.docker.internal", Port: 1111},
	}
	if !reflect.DeepEqual(sites, want) {
		t.Errorf("sites:\n got %+v\nwant %+v", sites, want)
	}
	if len(skipped) != 1 || skipped[0].Hostname != "php.example.com" || !strings.Contains(skipped[0].Reason, "php_fastcgi") {
		t.Errorf("skipped = %+v, want php.example.com for php_fastcgi", skipped)
	}
}
