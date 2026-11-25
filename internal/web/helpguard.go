package web

import "html/template"

// Help for the protection, traffic and alert pages (design: claudedocs/design_corvus_features.md).
func init() {
	for k, v := range map[string]string{
		"ban_on":           "Counts error responses (401, 403 and 429 by default) per visitor address. A visitor that reaches the limit in the window is refused for 15 minutes, then 1 hour, then 24 hours if they come back. Limits are on the Settings page, Protection tab. Pages that the layers themselves answer never count.",
		"ban_manual":       "One IPv4 address, or an IPv6 /64 (a whole home network). You cannot ban the address you are using. Bans apply to every site that has auto-ban switched on.",
		"ban_codes":        "Response status codes that count toward a ban. 404 is not in the default list on purpose: pages with a missing picture would ban normal visitors. Add it only for sites that should never see a miss.",
		"ban_steps":        "How long each ban lasts, in minutes, one number per repeat offence. The last step repeats. A client that was banned in the last 7 days starts at the next step.",
		"ban_unknown_host": "Requests for names no site owns are always answered 404 and counted. Tick this to let them feed the ban as well, which stops scanners that probe by IP address.",
		"ua_mode":          "On: every visitor must pass a short check before the site loads. Auto: the check switches on by itself while requests per second stay above the trigger and off after the cool-down. Addresses on the site's IP allowlist and the certificate paths are never challenged.",
		"ch_kind":          "Proof of work runs in the visitor's browser and needs no outside service. Turnstile uses Cloudflare and needs TURNSTILE_SITE_KEY and TURNSTILE_SECRET set, and the site's names allowed in the widget.",
		"ch_difficulty":    "How much work a browser does: low about a fifth of a second, medium about a second, high several seconds on a phone. These are guides; test on your own devices.",
		"ua_auto":          "The auto trigger looks at requests per second over the last ten seconds. Leave it at 0 for a manual switch only.",
		"q_on":             "Holds visitors above the capacity in a waiting room that reloads itself when their turn comes. Admitted visitors keep their place while they stay active. Use the release button if you need everyone in at once.",
		"backends":         "More upstreams for the same site, host:port one per line. Requests rotate across all of them, and one that fails is skipped for 30 seconds. Proxy sites only; they share the upstream scheme and the TLS setting above.",
		"x402_routes":      "One paid path per line: the path prefix, the price in US dollars, all or bots (bots means crawlers on the bot list, visitors who skipped a challenge and requests the firewall flagged), request or token (a token lets the payer in for the given seconds), and the token lifetime. Example: /api/ 0.001 bots token 600. The wallet and facilitator are on the Settings page, Protection tab.",
		"alert_site":       "Tick destinations to send this site's alerts to those only. Leave all unticked to use every destination that listens for the event.",
		"alert_kinds":      "ntfy: the topic address. Webhook: an https address and a signing key; the body is signed with HMAC-SHA256 in X-ServanaGo-Signature (the timestamp header is part of what is signed). Email: the address; needs email delivery on Settings. Pushover: the user key as address and the application token as secret. SMS: the two numbers, sender then recipient, written as from,to and the credentials as SID:auth token.",
		"page_status":      "200 to 599. A 301, 302, 303, 307 or 308 with a target is a redirect; any other status serves the page. 503 with a short message suits maintenance, 200 a parked name.",
		"page_html":        "Optional. Written exactly as you type it and served as is; placeholders in braces are not replaced. Up to 64 KB.",
		"ua_list":          "Crawler names, separated by spaces, matched anywhere in the visitor's User-Agent without regard to case. They are the bots a paywall in bots mode charges.",
		"x402_facilitator": "The service that checks and settles payments, such as https://x402.org/facilitator for the test network. A paywall answers 503 until this and a wallet are set; it never serves paid content unchecked.",
	} {
		hints[k] = v
	}
	helpSections = append(helpSections,
		helpSection{"traffic", "Traffic", template.HTML(`
<p>The <strong>Traffic</strong> page shows what every site is serving: requests, the status classes, latency percentiles, and how many requests the protection layers answered themselves (blocked, challenged, queued, banned, paywalled). The live view refreshes every two seconds while the page is open; the other ranges come from per-minute rollups kept for the number of days set under Settings, Protection.</p>
<p>The request log keeps the path (never the query string), the client address, the user agent and the origin of the referrer, for 7 days by default. Filter it, or export it as CSV. A site's recent failed upstream requests appear here too: filter by status 502 or 504 to see why.</p>
<p>Visitors behind Cloudflare appear under their own address, not Cloudflare's: ServanaGo trusts the <code>CF-Connecting-IP</code> header only from Cloudflare's published ranges.</p>`)},
		helpSection{"bans", "Bans", template.HTML(`
<p>A ban refuses every request from an address (an IPv6 /64 for IPv6) with a plain 403. Auto-ban is a per-site switch on the Protection tab; the rules (which status codes, how many, how long) are on Settings, Protection. Bans escalate: the first lasts 15 minutes, a repeat within a week an hour, then a day. A ban survives a restart.</p>
<p>Never banned: loopback and private addresses, Cloudflare's own nodes, the ranges you list as never-ban, and addresses on the site's IP allowlist. You cannot ban the address you are using.</p>`)},
		helpSection{"alerts", "Alerts", template.HTML(`
<p>An alert destination is somewhere ServanaGo sends a short message: an ntfy topic, a signed webhook (the way to reach Slack, Discord, Mattermost or Teams through a small relay), an email address, Pushover or an SMS through Twilio. Each destination picks the events it hears: under-attack on or off, bans, a full waiting room, a backend going down or up, x402 payment trouble, virus scans and failed backups.</p>
<p>One attempt is made per message, five seconds at most; a failure shows on the destination's row. The same event for the same site is sent once per five minutes. A site can name its own destinations on its Protection tab.</p>
<p>Addresses, tokens and keys are stored sealed with the secret key and cannot be read back. Webhooks must be https, and nothing is sent to loopback, private or link-local addresses.</p>`)},
		helpSection{"protection", "Protection layers", template.HTML(`
<p>Each site's <strong>Protection</strong> tab switches layers on. They run in this order for every request: the traffic recorder, <strong>ban</strong>, country filter, firewall (with its rate limit), <strong>under-attack challenge</strong>, the gate or IP allowlist, basic authentication, the <strong>x402 paywall</strong>, the <strong>access queue</strong>, snippets, then the site. Addresses on the site's IP allowlist skip the challenge, the paywall and the queue.</p>
<p><strong>Under-attack mode</strong> asks every visitor for a short proof of work (or a Cloudflare Turnstile check) and then remembers them for the pass time. <strong>Auto</strong> turns it on while traffic stays above a requests-per-second trigger. <strong>The access queue</strong> admits a set number of visitors at a time and holds the rest in a waiting room. <strong>The paywall</strong> answers HTTP 402 and takes a USDC payment on Base through an x402 facilitator before serving the path; payments are real money on the Base mainnet, so try the Base Sepolia test network first.</p>
<p>Extra backends give a proxy site failover, and a site of kind <em>Page</em> serves a maintenance or parked page, or redirects to another address, with the same protection layers.</p>
<p>Since 0.22.0 an IP allowlist is matched against the visitor's address, not Cloudflare's: on a Cloudflare-proxied name it now lets the listed visitors in and keeps the rest out.</p>`)},
	)
}
