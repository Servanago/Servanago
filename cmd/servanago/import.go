package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/servanago/servanago/internal/caddyfile"
	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/dnssync"
	"github.com/servanago/servanago/internal/store"
)

// runImport implements `servanago import [-dry-run] <Caddyfile>`. It writes SQLite and Cloudflare directly and
// does not touch a running Caddy: stop the service first, then start it to serve the imported routes.
// It needs Cloudflare (zone lookup and A records), so it refuses to run without CLOUDFLARE_API_TOKEN.
func runImport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "show what would be imported; change nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: servanago import [-dry-run] <Caddyfile>")
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	if !cfg.DNSEnabled() {
		return errors.New("import looks up Cloudflare zones and creates DNS records: set CLOUDFLARE_API_TOKEN (and SERVANAGO_HOST_IP) first")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	sites, skipped := caddyfile.Parse(f)
	for _, s := range skipped {
		fmt.Fprintf(out, "skip %s: %s\n", s.Hostname, s.Reason)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "servanago.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	var cfOpts []option.RequestOption
	if cfg.CFBaseURL != "" {
		cfOpts = append(cfOpts, option.WithBaseURL(cfg.CFBaseURL))
	}
	cf := cfdns.New(cfg.CloudflareToken, cfOpts...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return importer{cfg: cfg, cf: cf, st: st, dns: dnssync.New(cf, st), parserSkipped: len(skipped)}.run(ctx, sites, *dry, out)
}

type importer struct {
	cfg config.Config
	cf  *cfdns.Client
	st  *store.Store
	dns *dnssync.Syncer

	parserSkipped int // blocks the Caddyfile reader could not model; counted in the summary
}

// run adds each site as a route (creating its domain on first use) and reconciles its A record.
// A site that cannot be imported is reported and skipped; existing routes are left alone, so reruns are safe.
func (im importer) run(ctx context.Context, sites []caddyfile.Site, dry bool, out io.Writer) error {
	domains, err := im.st.ListDomains(ctx)
	if err != nil {
		return err
	}
	routes, err := im.st.ListRoutes(ctx)
	if err != nil {
		return err
	}
	exists := map[string]bool{}
	for _, r := range routes {
		for _, d := range domains {
			if d.ID == r.DomainID {
				exists[r.Subdomain+"."+d.Name] = true
			}
		}
	}
	added, skipped := 0, im.parserSkipped
	skip := func(host, why string) { skipped++; fmt.Fprintf(out, "skip %s: %s\n", host, why) }
	for _, s := range sites {
		host := strings.ToLower(s.Hostname)
		if err := config.ValidateDomain(host); err != nil {
			skip(host, err.Error())
			continue
		}
		if host == im.cfg.Host {
			skip(host, "is the ServanaGo UI host")
			continue
		}
		if exists[host] {
			skip(host, "route already exists")
			continue
		}
		maxBody := int64(0)
		if s.MaxBody != "" {
			if maxBody, err = config.ParseSize(s.MaxBody); err != nil {
				skip(host, "request_body max_size: "+err.Error())
				continue
			}
		}
		dom, err := im.domainFor(ctx, &domains, host, dry)
		if err != nil {
			skip(host, err.Error())
			continue
		}
		sub := strings.TrimSuffix(host, "."+dom.Name)
		if host == dom.Name || strings.Contains(sub, ".") {
			skip(host, fmt.Sprintf("must be exactly one label below %s", dom.Name))
			continue
		}
		rt := store.Route{DomainID: dom.ID, Subdomain: sub, Scheme: s.Scheme, UpstreamHost: s.Host, UpstreamPort: s.Port,
			TLSSkipVerify: s.SkipVerify, Enabled: true, Stream: s.Stream, MaxBody: maxBody}
		if !dry {
			created, err := im.st.CreateRoute(ctx, rt)
			if err != nil {
				skip(host, err.Error())
				continue
			}
			_ = im.dns.Reconcile(ctx, created.ID) // failures are recorded on the DNS row, shown in the UI
		}
		exists[host] = true
		added++
		fmt.Fprintf(out, "add  %s -> %s://%s:%d\n", host, s.Scheme, s.Host, s.Port)
		if len(s.Dropped) > 0 {
			fmt.Fprintf(out, "warn %s: not imported: %s\n", host, strings.Join(s.Dropped, ", "))
		}
	}
	verb := "added"
	if dry {
		verb = "would add"
	}
	fmt.Fprintf(out, "%s %d, skipped %d\n", verb, added, skipped)
	return nil
}

// domainFor returns the managed domain enclosing host, creating it from Cloudflare's zone list when new.
// In a dry run a new domain is only described (ID 0).
func (im importer) domainFor(ctx context.Context, domains *[]store.Domain, host string, dry bool) (store.Domain, error) {
	var best *store.Domain
	for i, d := range *domains {
		if strings.HasSuffix(host, "."+d.Name) && (best == nil || len(d.Name) > len(best.Name)) {
			best = &(*domains)[i]
		}
	}
	if best != nil {
		return *best, nil
	}
	if _, err := config.ValidateLANIP(im.cfg.HostIP); err != nil {
		return store.Domain{}, fmt.Errorf("SERVANAGO_HOST_IP: %w", err)
	}
	zoneID, zone, err := im.cf.ZoneFor(ctx, host, "")
	if err != nil {
		return store.Domain{}, err
	}
	d := store.Domain{Name: zone, ZoneID: zoneID, DefaultIP: im.cfg.HostIP, CertMode: "wildcard"}
	if !dry {
		if d, err = im.st.CreateDomain(ctx, d); err != nil {
			return store.Domain{}, err
		}
	}
	*domains = append(*domains, d)
	return d, nil
}
