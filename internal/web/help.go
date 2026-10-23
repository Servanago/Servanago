package web

import (
	"fmt"
	"html"
	"html/template"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/config"
)

// All user-facing help lives here so form hints, status tooltips, error explanations and the /help
// page share one source. A test fails if a template references a hint or help section that is missing.

// hints are one-line, plain-text field explanations (rendered by the hint template func).
var hints = map[string]string{
	"domain":          "The Cloudflare zone your sites live in, such as example.com. Add it once; sites like oc.example.com go under it.",
	"default_ip":      "The address your sites' DNS records point to: this server, the machine running ServanaGo. Use its IPv4 address: public, or private (192.168.x.x, 10.x.x.x, 172.16-31.x.x, 100.64-127.x.x for Tailscale).",
	"default_ip6":     "Optional. The server's IPv6 address, so sites also get AAAA records and are reachable over IPv6. Leave blank to publish IPv4 only.",
	"zone":            "Only needed when the Cloudflare zone is not this domain's own name: for lab.example.com inside the zone example.com, type example.com. Leave blank to keep the zone as it is.",
	"cert_mode":       "Wildcard gets one *.example.com certificate for every site, so adding sites is instant and site names stay private. Per host gets a separate certificate for each site.",
	"hostnames":       "The addresses people type, one per line, such as oc.example.com. The first is the main one. Any name works: if its Cloudflare zone is found ServanaGo adds the DNS record for the main name; otherwise point the name at this server yourself and its certificate comes from HTTP-01.",
	"hostnames_nodns": "The addresses people type, one per line, such as oc.example.com. The first is the main one. Point each name at this server in your DNS yourself; certificates come from HTTP-01, so ports 80 and 443 must be reachable from the internet.",
	"kind":            "Proxy forwards requests to an app running on this or another machine. Static serves the files in a folder on this machine. Node.js, PHP and FrankenPHP are apps this machine supervises: ServanaGo creates a system user, sandboxed systemd unit and (for PHP) a per-site pool, and never installs the runtime itself.",
	"node_port":       "The port YOUR app process listens on, such as 3000. It must accept connections on 127.0.0.1 (loopback) — Caddy front-end in front of it.",
	"franken_port":    "The loopback port FrankenPHP listens on, such as 8100. ServanaGo starts it with this port; it must be free and different from every other Node.js or FrankenPHP site's port.",
	"fcgi_addr":       "Where your FastCGI app listens: an absolute path to a Unix socket such as /run/myapp/fcgi.sock, or host:port such as 127.0.0.1:9000. ServanaGo never starts it, so the socket must be readable and writable by the servanago user.",
	"start":           "The command that runs forever, such as `node server.js` or `bun run start`. Systemd runs it as the site's own unprivileged user and restarts it if it crashes. Do not use sudo here.",
	"installcmd":      "Optional: the command that installs the project's dependencies, such as `npm ci`. ServanaGo shows it for you to run on the server as the site user — nothing runs it for you.",
	"buildcmd":        "Optional: the command that builds the project, such as `npm run build`. Like the install command, it is shown for you to run by hand.",
	"static_root":     "The folder to serve, as an absolute path such as /srv/www/blog or /home/me/public_html. Directory listings are off and files whose names start with a dot are never served. The user ServanaGo runs as needs read access to the folder and execute access to every folder above it; ServanaGo never changes permissions.",
	"domain_nodns":    "The name your sites live under, such as example.com. Add it once; sites like oc.example.com go under it.",
	"scheme":          "How Caddy talks to your app. Use http unless the app itself serves HTTPS.",
	"upstream_host":   "Where the app really runs: an IP address such as 192.168.25.165, or a host name that resolves on this server. Not the public hostname.",
	"upstream_port":   "The port the app listens on, such as 9200 (a Node.js app is often 3000). Not 443: Caddy already provides HTTPS in front of it.",
	"site_user":       "The Linux user the site runs as, one site per user. Blank takes the first hostname (cut to 32 characters). For an existing user, ServanaGo only checks it: it must be a regular account, not a member of sudo, adm, wheel, admin or another root-equivalent group, and the folder must be inside its home. A site keeps its user; deleting the site leaves the user.",
	"user_home":       "Only for a new user: its home folder, one directory under /home or /srv that does not exist yet. ServanaGo creates it with the folder below, owned by the user; the user has no password and no ssh keys.",
	"shell_login":     "A new user gets /bin/bash only if you tick this; otherwise it cannot log in. With a shell, anyone who can sign in here can reach the host as that user (a start command can add an ssh key), so leave it off unless you need it. A PHP site's user then gets the site's PHP as php and composer.",
	"public_dir":      "Optional: the folder inside the one above that visitors can reach, such as public for Laravel or Slim. Code, vendor and .env above it are never served. Blank serves the whole folder.",
	"fpm_version":     "The php-fpm binaries installed on this host, newest first. If the list is empty, build PHP on the PHP page or install a distribution package, then reload this page.",
	"php_ext":         "Which PHP extensions this site loads. They apply to PHP that ServanaGo built itself (PHP page); a distro PHP keeps its own php.ini. With none ticked the site gets the core set: mbstring, opcache, sqlite3 and pdo_sqlite. openssl, xml parsing support, zlib, session, ctype, tokenizer, fileinfo, phar and PDO are always on. PHP 8.5 and later always include opcache. apcu and imagick are PECL extensions built into the same PHP build; a build made before they were offered does not have them, so build PHP again to use them.",
	"php_health_path": "Optional. After a PHP switch, ServanaGo requests this path of the site (for example /healthz) and keeps the new PHP only if it answers below 400; otherwise it goes back to the previous build. Leave empty to check only that php-fpm stays up. If the site is behind the magic-link gate or basic auth, the path must be reachable without signing in, or leave this empty.",
	"skip_verify":     "Only for apps that use https with a self-signed certificate. Turns off checking that certificate. Fine on a trusted home network.",
	"stream":          "Sends the app's answer to the visitor as it arrives instead of in chunks. Turn on for live streams, event feeds and terminals that seem to freeze or lag. Websockets work without it.",
	"max_body":        "The biggest upload this site accepts, such as 2GB or 512MB (up to 100GB). Larger uploads get error 413. Leave empty for no limit.",
	"snippets":        "Caddyfile snippets from the Snippets page that apply to this site, in name order. They run after the access checks and before the site itself. Paths under /.well-known/ are never touched by a snippet.",
	"snippet_rules":   "Allowed: named matchers with respond, error, redir, header, request_header, request_body and encode. Anything that serves, proxies or authenticates is refused. Paths under /.well-known/ always bypass snippets. Snippets of a site run in name order, after its access checks and before the site itself.",
	"notes":           "Your own notes about this site (owner, purpose, things to remember), up to 10,000 characters. Plain text. Shown on the Reference page; nothing here changes how the site is served.",
	"extra_routes":    "Sends certain paths of this site to a different app. One per line in the form path=dial, such as /cryptpad_websocket=127.0.0.1:3303 (dial is also an absolute socket path such as /run/api.sock). The path matches itself and everything below it. Any access control still applies first.",
	"record_ip":       "Leave blank to use the domain's default IP. Set it only if this one site's DNS record must point at a different server.",
	"record_ip6":      "Leave blank to use the domain's default IPv6 address (or none). Set it only if this one site's AAAA record must point at a different server.",
	"allowlist":       "Only these networks can open the site; everyone else gets an error 403. If magic-link access is on, these networks skip the link and everyone else asks for one instead of getting the 403. One per line. Leave empty to allow anyone who can reach this server. Example: 192.168.0.0/16 is a typical whole home network.",
	"basic_auth":      "Puts a username and password prompt in front of the app. Leave the user empty for no prompt.",
	"enabled":         "Turn off to stop serving the site without deleting it. Caddy ignores it completely, so no certificate work happens for it. Its DNS record is kept.",
	"admin_login":     "The password set as ADMIN_PASSWORD when ServanaGo was started.",
	"totp_code":       "The 6-digit code from your authenticator app. A backup code also works, once.",
	"backup_codes":    "Each code works once if you lose your authenticator. Keep them somewhere safe; they are not shown again.",
	"passkey_name":    "A label so you can tell your passkeys apart, such as Laptop or Phone.",
	"secret_key":      "Authenticator codes are stored encrypted. Set SERVANAGO_SECRET_KEY (at least 32 characters, for example from openssl rand -hex 32) in the environment file and restart ServanaGo to turn them on. Back it up with your data directory.",
	"gate_mode":       "A magic link (sent by email, valid for 15 minutes and single-use) opens the site only after it is clicked. The link opens on the site's main hostname with ml. in front, which ServanaGo adds to Cloudflare DNS and Caddy for you; other hostnames of the site send visitors to the main one. With the allowlist, only listed emails and @domain rules get a link; with any email, anyone with a working inbox can ask for one.",
	"gate_acl":        "One rule per line: alice@example.com admits exactly that address; @contractor.example admits everyone at that domain. Rules are matched after lowering case; a session is shared between all gated sites that allow the address. On an existing site the rules are the list below, with their own Add and Remove buttons.",
	"gate_provider":   "How this site's links are mailed. SMTP uses a submission server; Postmark uses its HTTP API with a server token. Every gated site has its own provider and credential, separate from the Settings page.",
	"gate_secret":     "The SMTP password or the Postmark server token. It is stored encrypted with SERVANAGO_SECRET_KEY and never shown again; leave blank to keep the stored one.",
	"gate_rows":       "Each row admits one address, or a whole domain when it starts with @. Removing a row ends the session of anyone it no longer admits. Changes apply at once, without a save.",
	"username":        "Lower-case letters, digits, '.', '_' and '-', up to 32 characters. They type it on the sign-in page.",
	"new_password":    "At least 8 characters. It is stored as a bcrypt hash, never in the clear. The person can change it on their Security page.",
	"reauth":          "Adding, removing or resetting an administrator is sensitive, so it asks for your own password again, plus a code from your authenticator or a backup code if you use one.",
	"smtp_host":       "The submission server your provider gives you, such as smtp.fastmail.com. Leave empty (with MAIL FROM) to stop sites from sending.",
	"smtp_port":       "587 (STARTTLS submission) for most providers.",
	"smtp_pass":       "Stored encrypted with SERVANAGO_SECRET_KEY and never shown again. Leave blank to keep the stored one, or for relays that do not ask for a password.",
	"mail_from":       "The sender address on the magic-link emails, such as access@example.com. Your provider must allow it.",
	"smtp_setup":      "Magic-link access needs SERVANAGO_SECRET_KEY in the environment file and a connected Cloudflare account (the site's ml. host gets its DNS records there). Mail is set per site, in the site's own form.",
}

// statusHelp explains every status word and what to do next. Keys are kind:state.
type statusInfo struct{ Label, Meaning, Next string }

var statusOrder = []string{"cert:issued", "cert:pending", "cert:expiring", "cert:error", "dns:synced", "dns:pending", "dns:conflict", "dns:error", "up:up", "up:down"}

var statusHelp = map[string]statusInfo{
	"cert:issued":   {"Certificate issued", "A valid HTTPS certificate is being served for this site.", ""},
	"cert:pending":  {"Certificate pending", "ServanaGo is still getting the certificate from Let's Encrypt. It proves it owns the domain either with a check over the internet (ports 80 and 443 must be reachable) or, with Cloudflare, by writing a temporary DNS record and waiting for Cloudflare to publish it.", "Wait; the first one can take several minutes. Watch the Logs page if it takes longer."},
	"cert:expiring": {"Certificate expiring soon", "The certificate expires in less than three weeks. Caddy normally renews it a month early, so renewal is overdue or failing.", "Open the Logs page and look for certificate errors."},
	"cert:error":    {"Certificate error", "Getting or serving the certificate failed.", "Read the explanation shown with it, then check the Logs page."},
	"dns:synced":    {"DNS in sync", "The A record in Cloudflare exists and points where this site expects.", ""},
	"dns:pending":   {"DNS not yet synced", "ServanaGo has not created or checked this site's A record yet.", "Press Resync."},
	"dns:conflict":  {"DNS conflict", "An A record with this name already exists and points somewhere else. ServanaGo did not touch it.", "Press Take over to replace it, or fix it in Cloudflare and press Resync."},
	"dns:error":     {"DNS error", "Talking to Cloudflare failed. The site itself still works if its record already exists.", "Read the explanation shown with it, then press Retry."},
	"up:up":         {"Backend reachable", "ServanaGo can open a connection to the app's address and port.", ""},
	"up:down":       {"Backend unreachable", "Nothing answered at the app's address and port, so visitors will get an error.", "Check the app is running, and that the host and port are right and reachable from this server."},
}

// explained is a plain-language version of a known technical error.
type explained struct{ Title, Fix string }

var errTable = []struct {
	match string // lower-case substring
	explained
}{
	{"timed out waiting for record to fully propagate", explained{"Cloudflare was slow to publish the verification record",
		"This is common and ServanaGo keeps retrying. If it never succeeds, raise ACME_PROPAGATION_TIMEOUT (and ACME_PROPAGATION_DELAY) in the environment file and restart ServanaGo."}},
	{"no cloudflare zone found", explained{"That domain's zone was not found in Cloudflare",
		"Check the spelling, that the domain is added to your Cloudflare account, and that the API token can read that zone."}},
	{"the token cannot see it", explained{"That domain's zone was not found in Cloudflare",
		"Check the spelling, that the domain is added to your Cloudflare account, and that the API token can read that zone."}},
	{"cannot be decrypted", explained{"The saved authenticator cannot be opened",
		"SERVANAGO_SECRET_KEY is missing or different from when it was set up. Restore the old key, use a backup code, or run servanago 2fa-reset."}},
	{"multiple a records", explained{"More than one A record has this name",
		"Delete the extra records in Cloudflare so only one is left, then press Resync."}},
	{"invalid access token", explained{"Cloudflare rejected the API token",
		"Create a new token with Zone:Read and DNS:Edit, put it in the environment file as CLOUDFLARE_API_TOKEN, and restart ServanaGo."}},
	{"verify cloudflare token", explained{"Cloudflare rejected the API token",
		"Create a new token with Zone:Read and DNS:Edit, put it in the environment file as CLOUDFLARE_API_TOKEN, and restart ServanaGo."}},
	{"must be a usable ipv4", explained{"That address cannot be used",
		"Use the IPv4 address of the server, for example 203.0.113.10 or 192.168.1.10. Not 127.x.x.x, 169.254.x.x, 0.0.0.0, a multicast or reserved address, or an IPv6 address."}},
	{"must be a usable ipv6", explained{"That address cannot be used",
		"Use the IPv6 address of the server, for example 2001:db8::10. Not ::1, an fe80:: address, a multicast address, an IPv4-mapped address or an IPv4 address."}},
	{"is the servanago ui host", explained{"That name is ServanaGo's own address",
		"Choose a different hostname for this site."}},
	{"caddy rejected config", explained{"Caddy rejected the configuration",
		"Nothing was changed. The detail below says which setting Caddy did not accept."}},
	{"ratelimited", explained{"Let's Encrypt rate limit reached",
		"Too many certificates were requested recently. Wait before retrying, or set ACME_STAGING=true while testing."}},
	{"too many certificates", explained{"Let's Encrypt rate limit reached",
		"Too many certificates were requested recently. Wait before retrying, or set ACME_STAGING=true while testing."}},
	{"context canceled", explained{"The attempt was interrupted",
		"This usually happens during a restart. It retries automatically."}},
	{"is already used by another site", explained{"That hostname already belongs to a site",
		"Open that site from the dashboard to change it, or choose a different hostname."}},
}

// explain returns a plain-language explanation for known errors only; unknown errors are shown raw.
func explain(msg string) (explained, bool) {
	l := strings.ToLower(msg)
	for _, e := range errTable {
		if strings.Contains(l, e.match) {
			return e.explained, true
		}
	}
	return explained{}, false
}

// errorHTML renders msg for display: the plain-language explanation first (if known), the raw text always.
func errorHTML(msg string) string {
	raw := html.EscapeString(msg)
	e, ok := explain(msg)
	if !ok {
		return raw
	}
	return "<strong>" + html.EscapeString(e.Title) + ".</strong> " + html.EscapeString(e.Fix) + "<br><small>" + raw + "</small>"
}

// certWait is the longest Caddy waits for one DNS-01 attempt: the delay before checking plus the timeout.
func certWait(delay, timeout time.Duration) string {
	if timeout == 0 {
		timeout = 2 * time.Minute // Caddy's default
	}
	mins := int((delay + timeout).Round(time.Minute) / time.Minute)
	return fmt.Sprintf("The first certificate can take up to %d minutes. It retries on its own; the Logs page shows progress.", mins)
}

type helpSection struct {
	ID, Title string
	Body      template.HTML // trusted static markup
}

var helpSections = []helpSection{
	{"how-it-works", "How ServanaGo works", `
<p>ServanaGo puts your web apps behind real web addresses with valid HTTPS. For each <strong>site</strong>, such as <code>oc.example.com</code>, it does three things:</p>
<ol>
<li>Points the name at this server. With a Cloudflare token ServanaGo creates the <strong>DNS records</strong> (A, and AAAA if you gave an IPv6 address) itself; without one, you point the name at this server in your own DNS.</li>
<li>Gets an <strong>HTTPS certificate</strong> from Let's Encrypt. Without Cloudflare it proves it owns the name with a check over the internet, so ports 80 and 443 must be reachable. With Cloudflare it writes a temporary record there instead, so this server never needs to be reachable from the internet, and a domain can share one wildcard certificate.</li>
<li>Tells <strong>Caddy</strong> (the web server inside ServanaGo) to forward requests for that name to your app's <strong>backend</strong>: its IP address and port, such as <code>192.168.25.165:9200</code>.</li>
</ol>
<p>Every change is checked by Caddy before it goes live. If Caddy rejects it, nothing changes and you see the reason.</p>`},
	{"sites", "Sites, domains and ports", `
<p>A <strong>site</strong> answers on one or more <strong>hostnames</strong>, such as <code>oc.example.com</code>: any valid public name, with any number of labels, one per line, the first being the main one. A <strong>domain</strong> is optional context for DNS and certificates: the Cloudflare zone, default IPs and certificate mode that apply to the hostnames under it, such as <code>example.com</code>. With Cloudflare, <strong>Add site</strong> finds the zone and adds the domain the first time. A hostname with no domain is still served, with its own certificate from the HTTP-01 check, and ServanaGo creates no DNS record for it.</p>
<p>A site is either a <strong>proxy</strong> or <strong>static</strong>. A proxy forwards to an app: the <strong>backend port</strong> is the port that app listens on and differs for every app. It is not 443; Caddy provides HTTPS in front of it. The DNS record points at this server, not at the backend, so the backend can be on another machine. A static site serves the files in a <strong>folder</strong> on this machine, with no directory listings and no files whose names start with a dot.</p>
<p>The folder is checked when you save: it must exist, and system folders (<code>/etc</code>, <code>/proc</code>, <code>/sys</code>, <code>/dev</code>, <code>/root</code>, the data directory) are refused. <code>SERVANAGO_STATIC_ROOTS</code> can limit folders to chosen prefixes. ServanaGo never changes permissions: the user it runs as needs read access to the folder and execute access to every folder above it, and the site page says when it cannot read the folder.</p>`},
	{"sign-in", "Sign-in security", `
<p>Under <strong>Security</strong> you can add an <strong>authenticator app</strong> (a 6-digit code after the password) and <strong>passkeys</strong> (sign in with your fingerprint, face or device PIN instead of the password). A passkey sign-in counts as full two-factor, so it asks for no code. Passkeys work only on the HTTPS address, or on <code>localhost</code>.</p>
<p>If you lose your authenticator and passkeys, use a backup code. If those are gone too, run <code>servanago 2fa-reset</code> on the server: it removes all of them and the password works alone again.</p>
<p>Setting <code>TURNSTILE_SITE_KEY</code> and <code>TURNSTILE_SECRET</code> adds a Cloudflare Turnstile check to the password form on the HTTPS address. The recovery address (<code>UI_LISTEN</code>) skips it.</p>`},
	{"certificates", "Certificates: wildcard or per host", `
<p><strong>Wildcard</strong> (the default) gets one certificate for <code>*.example.com</code> that covers every site under the domain. New sites are instant, and the names of your sites stay out of public certificate logs.</p>
<p><strong>Per host</strong> gets a separate certificate for each site, which is slower for each new site. A wildcard covers one level only: <code>oc.example.com</code> yes, <code>a.oc.example.com</code> no.</p>`},
	{"statuses", "What the status words mean", ``}, // table is generated from statusHelp
	{"token", "The Cloudflare token (optional)", `
<p>Cloudflare is optional: without a token ServanaGo uses HTTP-01 certificates and manages no DNS. With a token it also creates the DNS records and can use wildcard certificates. The token needs two permissions on your zones: <strong>Zone &rarr; Zone &rarr; Read</strong> and <strong>Zone &rarr; DNS &rarr; Edit</strong>. Create it under My Profile, API Tokens. It is set as <code>CLOUDFLARE_API_TOKEN</code> in the environment file and is never stored in the database or shown here. After changing the file, restart ServanaGo.</p>`},
	{"addresses", "Which addresses can be used", `
<p>The <strong>A record</strong> target is the IPv4 address of the server: a <strong>public</strong> address, or a private one (10.x.x.x, 172.16-31.x.x, 192.168.x.x, or 100.64-127.x.x for Tailscale). A public address makes the site reachable from the internet; a private one only from your home network or tailnet. Loopback (127.x.x.x), link-local (169.254.x.x), multicast and reserved addresses cannot be used.</p>
<p>Optionally add the server's <strong>IPv6</strong> address (public, or unique-local fd00::/8) and ServanaGo also manages an <strong>AAAA record</strong>, so the site works over both IPv4 and IPv6. The IPv4 address is still required. Loopback (::1), link-local (fe80::), multicast and IPv4-mapped addresses cannot be used. Records are always DNS-only (never proxied).</p>`},
	{"access", "Limiting who can open a site", `
<p>On a site's edit page you can limit it to certain networks (<strong>Allowed sources</strong>, for example <code>192.168.0.0/16</code> for your whole home network) and add a <strong>username and password</strong>. Everyone else gets an error. The password is stored only as a hash.</p>
<p><strong>Magic-link access</strong> goes one step further: if you also list allowed networks, those networks walk straight in and everyone else gets the email form instead of a 403. The site asks for an email address and sends a single-use link from the site's own mail provider (SMTP or Postmark, set in the site's form). The link opens on <code>ml.</code> plus the site's main hostname, which hands you over to the site; a site's other hostnames redirect to the main one. Magic-link access needs Cloudflare, because ServanaGo creates the <code>ml.</code> DNS records there. The allowlist is a list of rows on the site's page: add or remove an address or <code>@domain</code> and it applies at once. Sessions last 30 days with an allowlist, 7 days with any email, sliding: activity extends them. Revoke one identity under <strong>Security</strong> and its access dies on every gated site at once.</p>`},
	{"runtimes", "Node.js, PHP, FrankenPHP, FastCGI and CGI sites", `
<p>A <strong>Node.js</strong> site is an app ServanaGo keeps running: it creates a system user (<code>sg-NAME</code>) and a sandboxed systemd unit that runs your <strong>start command</strong> in the app folder as that user, and Caddy forwards the hostname to the port you chose on <code>127.0.0.1</code>. The install and build commands are only noted for you: run them yourself on the server, as the site user (<code>sudo -u sg-NAME ...</code>), never as root.</p>
<p>A <strong>PHP</strong> site gets its own php-fpm pool and socket: as usual for php-fpm, the master process runs as root and its workers, the processes that run your PHP, drop to the site user. It uses the usual front-controller behaviour (<code>index.php</code> handles unknown paths). Pick the php-fpm version from those installed on the host.</p>
<p>A <strong>FrankenPHP</strong> site runs <code>frankenphp php-server</code> in your folder as the site user, on the loopback port you chose, and Caddy forwards the hostname to it. FrankenPHP serves both the static files and the PHP. ServanaGo only uses a <code>frankenphp</code> binary that is owned by root and not writable by anyone else, from <code>/usr/local/bin</code>, <code>/usr/bin</code> or <code>/opt/frankenphp</code>. Worker mode is not set up.</p>
<p>A <strong>FastCGI</strong> site connects Caddy to a FastCGI app you run yourself, over a socket or a port: every request goes to it. A <strong>CGI</strong> site runs executable scripts under <code>cgi-bin/</code> in the folder through <code>fcgiwrap</code>: ServanaGo creates a socket-activated unit that runs fcgiwrap as the site user, and only uses an <code>fcgiwrap</code> binary that is owned by root and not writable by anyone else. Both answer dotfile paths with 404.</p>
<p><strong>Folder access.</strong> ServanaGo never changes the ownership or permissions of your files. The site user (<code>sg-NAME</code>) must be able to read the folder (and write where the app stores uploads or caches), and to enter every folder above it. For example: <code>sudo setfacl -R -m u:sg-NAME:rX /path/to/site</code>, plus <code>sudo setfacl -m u:sg-NAME:x /home/you</code> for a folder under your home. Folder names with spaces or the characters % $ \ quotes are refused because they cannot be written safely into a systemd unit.</p>
<p>ServanaGo <strong>detects</strong> Node.js, php-fpm and FrankenPHP and shows the install command; it never installs a runtime, with one exception: it can compile PHP itself (<a href="#php-builds">PHP built from source</a>). Users on the same host are separated by Unix permissions, which is not a sandbox against hostile tenants: do not host mutually untrusted sites here.</p>
<p>A new site can run as its own <strong>user</strong>: a new one named after the site, or an existing regular account (never one in sudo, adm or wheel). One site per user. A new user has a locked password and no ssh keys, and no shell unless you tick the box. Its home and the folder <code>public_html</code> are created for it; the folder you serve must be inside that home. An optional <strong>public folder</strong> such as <code>public</code> is what visitors reach, so a framework's code and <code>.env</code> above it stay private. Deleting the site leaves the user: remove it as root when you are done (<code>userdel -r NAME</code> also deletes the home).</p>`},
	{"php-builds", "PHP built from source", `
<p>On the <strong>PHP</strong> page ServanaGo downloads a PHP release from php.net, compiles it with its own copies of the libraries it needs and installs it under <code>/opt/servanago/php</code>. Use it when a security release must not wait for your distribution's package mirrors. It never calls <code>apt</code>: the machine needs a C and C++ compiler, make, pkg-config, cmake, perl, bison, flex, autoconf, automake, libtool, m4, gpg, xz and tar, and the page lists any that are missing with the one <code>apt install</code> line that provides them. A build needs 10 GB of free disk space, takes tens of minutes and is limited to half the CPU and 4 GB of memory; sites keep serving meanwhile.</p>
<p><strong>What is checked.</strong> The PHP download must match the sha256 php.net publishes and carry a valid signature from a PHP release manager (the keys are built into ServanaGo). Each library is checked against the checksum its project publishes; libpng, freetype and libwebp are fixed to a known checksum, so a newer release of those arrives with a ServanaGo update. The extensions <strong>apcu</strong> and <strong>imagick</strong> come from Packagist and GitHub, which publish no checksum: ServanaGo trusts them over HTTPS at the commit Packagist names and writes that commit and the download's sha256 to the build log. Only branches php.net still supports can be built.</p>
<p><strong>Using a build.</strong> A site picks <code>8.4</code> (it follows the newest 8.4 build) or one exact build, and ticks the extensions it needs (PHP 8.5 and later always include opcache). <strong>Switch</strong> moves every site that follows a branch onto the newest build, one at a time: if a site's php-fpm does not stay up, or its optional health path answers an error, that site goes back to the previous build and the rest are left alone. A build that a site or user still uses cannot be removed. Builds made before an extension was offered do not contain it; build PHP again to get it.</p>
<p><strong>Command line.</strong> A login user can have a default <code>php</code> and <code>composer</code> (chosen on the PHP page). Nothing is written into the user's home or a site folder. <code>sudo php</code>, absolute paths such as <code>/usr/bin/php</code> and script shebangs ignore the setting.</p>
<p>ServanaGo checks php.net once a week and shows new releases for the branches you have built, security releases marked; it also emails the MAIL FROM address (Settings). It never builds or switches anything on its own.</p>`},
	{"users", "Administrators", `
<p>Everyone who can sign in is an <strong>administrator</strong> with the same powers: there are no roles. The first one is created from <code>ADMIN_PASSWORD</code> (and <code>ADMIN_USER</code>, default <code>admin</code>) the first time ServanaGo starts with no users; after that the variable is ignored and people are managed on the <strong>Users</strong> page.</p>
<p>Each administrator has their own password, authenticator app, backup codes and passkeys. Any administrator can add or remove another, set their password, or reset their second factor if they lose it; all of these end the other person's open sessions. You cannot remove yourself, and the last administrator cannot be removed.</p>
<p>If every administrator is locked out, run <code>servanago user passwd NAME</code> or <code>servanago 2fa-reset NAME</code> on the server (they read only <code>DATA_DIR</code>).</p>`},
	{"audit", "Audit log", `
<p>The <strong>Audit</strong> page lists what administrators did: signing in and out (and failed attempts, with the name that was typed and where it came from), creating, changing and deleting sites and domains, DNS resyncs, settings, adding and removing administrators, password and second-factor changes, and revoking site-visitor sessions. Each row has the time (UTC), who, what, the target and the client address.</p>
<p>Passwords, codes and tokens are never written to it. ServanaGo keeps the newest 10,000 rows. Actions run from the server's command line (<code>servanago user add</code>, <code>user passwd</code>, <code>2fa-reset</code>) appear as <code>cli</code>.</p>`},
	{"settings", "Settings: email delivery", `
<p>The <strong>Settings</strong> page holds ServanaGo's own email account: an <strong>SMTP host</strong> (usually port 587), optionally a <strong>user and password</strong>, and the <strong>MAIL FROM</strong> address. It sends ServanaGo's own notices, such as new PHP releases. The password is stored encrypted; <code>SERVANAGO_SECRET_KEY</code> still comes from the environment file.</p>
<p><strong>Magic links do not use this account.</strong> Each gated site has its own mail provider, SMTP or Postmark (a server token), with its own sender and credential, set in the site's form under <em>Magic-link access</em>. Use <em>Send test</em> on the site's page to check it. Saving the provider takes effect at once, with no restart.</p>`},
	{"troubleshooting", "Troubleshooting", ``}, // list is generated from errTable
}

// helpPage is the data for /help.
type helpPage struct {
	Sections []helpSection
	Statuses []statusInfo
	Errors   []explained
}

func newHelpPage() helpPage {
	p := helpPage{Sections: helpSections}
	for _, k := range statusOrder {
		p.Statuses = append(p.Statuses, statusHelp[k])
	}
	seen := map[string]bool{}
	for _, e := range errTable {
		if !seen[e.Title] {
			seen[e.Title] = true
			p.Errors = append(p.Errors, e.explained)
		}
	}
	return p
}

// helpFuncs are the template functions that render help consistently.
var helpFuncs = template.FuncMap{
	"hint": func(key string) template.HTML {
		return template.HTML("<small>" + html.EscapeString(hints[key]) + "</small>") // #nosec: escaped above
	},
	// hintid is hint with an id an input can name in aria-describedby; use it where each key appears once on the page.
	"hintid": func(key string) template.HTML {
		return template.HTML(`<small id="hint-` + html.EscapeString(key) + `">` + html.EscapeString(hints[key]) + `</small>`) // #nosec: escaped above
	},
	"helplink": func(anchor string) template.HTML {
		return template.HTML(`<a class="help-link" href="/help#` + html.EscapeString(anchor) + `" title="Open help" aria-label="Open help">?</a>`)
	},
	"size":   config.FormatSize,
	"icon":   icon,
	"status": func(kind, state string) statusInfo { return statusHelp[kind+":"+state] },
	"errhtml": func(msg string) template.HTML {
		return template.HTML(errorHTML(msg)) // #nosec: errorHTML escapes every piece
	},
}
