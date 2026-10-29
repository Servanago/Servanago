# Design: Postmark mail bridge (per-domain inbound → LMTP)

Settled scope is `claudedocs/requirements_next_features.md` §2 (2026-10-28). Reference designs:
`~/projects/gopmstall/{REQUIREMENTS,ARCHITECTURE,REFERENCE}.md` (design only, no shipped code) and the
verified prior art `~/projects/gopostmarkinbound/{hook.go,mime.go,autosetup.go}`.

## Scope

ServanaGo is the bridge between Postmark (internet-facing mail) and the admin's external mail server
(Stalwart or anything speaking LMTP). No mailbox store, no IMAP/JMAP, no outbound relay management
(gopmstall FR3), no Stalwart provisioning (FR6/FR7/FR8). Taken over: FR2 (inbound webhook → LMTP) and
FR4 (events endpoint + bounce DSN + event store). Provisioning covers FR1 steps 1–4 + FR5's
MX/SPF/DKIM/Return-Path (no MTA-STS, no DMARC).

## Webhook placement

Postmark POSTs to the panel host: `https://<SERVANAGO_HOST>/_mailbridge/hook/<domain>` and
`...//events/<domain>` — paths in the style gopmstall verified (`spike2-put-liveurl.json shows
`https://user:pass@host/hook/<domain>`). The panel host already has a route, certificate and DNS in
`caddycfg.Render` (`web.go:80`), so no Caddy change at all. Handlers mount on the top mux next to
`/mcp` (no cookie, no CSRF: basic-auth per domain, bcrypt, constant-time compare), and stay behind
`geoGuard` like everything else on the panel host. Documented caveat: a panel country rule that
refuses where the Postmark senders live will drop webhook POSTs (Postmark keeps retrying; mail is
still retrievable via Postmark). Payload size caps are constants: inbound 100 MiB (Postmark caps
inbound attachments at 35 MB and `RawEmail` roughly doubles the payload), events 5 MiB.

## Schema (`008_mail.sql`)

- `settings` new columns: `mail_pm_token BLOB` (secretbox-sealed Postmark **account** token),
  `mail_lmtp TEXT` (host:port, global target), `mail_lmtp_tls TEXT` ('' | starttls),
  `mail_lmtp_user TEXT`, `mail_lmtp_pass BLOB` (sealed). Per the settings-row convention
  (`Settings` struct + full row save), every save handler carries the new fields.
- `mail_domains`: per FQDN state. `name UNIQUE` (lowercase), `pm_server_id`, `pm_domain_id`
  (0 = not created), `dkim_host`/`dkim_text` (the published TXT pair), `return_path`
  (`pm-bounces.<domain>` CNAME name), `hook_user` + `hook_pass_hash` (bcrypt),
  `dns_notes` (`TEXT`, newline-separated notes: written rows, hand-publish hints, foreign SPF),
  `dkim_state`/`rp_state` (`'' | pending | verified | failed`), `last_verify` (epoch),
  `lmtp_addr` (per-domain override of the global endpoint; empty = global),
  counters `recv, delivered, deduped, rejected, fallbacks`, `last_inbound`, `created_at`.
  The Postmark server token is **not** stored: `GET /servers/{id}` returns `ApiTokens`
  (verified spike2 fixture) and nothing in scope reads it.
- `mail_events`: `domain_id FK`, `record_type` (Postmark `RecordType`), `record_id` (bounce ID),
  `message_id`, `email`, `summary` (one line), `payload` (raw JSON, bounded),
  `dsn_sent` (0/1), `created_at`. Index `(domain_id, created_at)`.
- `mail_delivered`: `key TEXT PRIMARY KEY` (sha256 of `messageID|recipient`, or `bounce:<id>`),
  `domain_id`, `created_at`. The authoritative dedupe store.

## Postmark clients (`internal/postmark/admin.go`)

`Client` stays the gate's server-token sender. New `Admin{AccountToken}` on the same
`X-Postmark-Account-Token` conventions, endpoints verified in gopmstall's spikes:

- `Servers()` / `Domains()`: paginated lists (`count`/`offset`; count max 200) for name lookup.
- `CreateServer(name)`, `UpdateServer(id, ServerConfig)`: `PUT /servers/{id}` with the account
  token sets `InboundHookUrl`, `RawEmailEnabled`, `BounceHookUrl`, `DeliveryHookUrl`,
  `IncludeBounceContentInHook`, `EnableSmtpApiErrorHooks`, `InboundDomain` (all verified settable).
- `CreateDomain(name)` posts `{Name, ReturnPathDomain: pm-bounces.<name>}`; DKIM is generated
  lazily: first call's response carries `DKIMPendingHost`/`DKIMPendingTextValue` (the TXT pair to
  publish). `VerifyDkim(id)` / `VerifyReturnPath(id)` are PUTs returning `{Valid}`.
- Postmark replies wrap errors as `{ErrorCode, Message}` with 422 status; treat 2xx +
  `ErrorCode == 0` as success.

## Provisioning (web Mail page + MCP `create_mail_domain`)

1. Validate + lowercase the domain (reuse `config.ValidateDomain`; reject `.local` etc.).
2. Look up a Postmark server named `mail-<domain>` and a Postmark domain `<domain>`; when one
   exists and `adopt` is not set, stop and tell the admin exactly what exists (gopmstall: warn,
   update only on explicit approval). With `adopt`, the flow reuses them and re-pushes our config
   (including the hooks).
3. Create what is missing; generate the webhook credential (`hook_user`/random password, bcrypt,
   shown once).
4. Synchronous part ends here — the web POST answers quickly; the rest is detached:
5. DNS through `cfdns` CRUD (only create or fix rows commented "managed by servanago"; never
   delete; an existing foreign SPF stays untouched and surfaces as a note): MX 10
   `inbound.postmarkapp.com`, SPF `v=spf1 include:spf.mtasv.net ~all`, the DKIM TXT, the
   `pm-bounces` CNAME. Zone from `ZoneFor`; no zone → per-record hand-publish notes.
6. After MX is written, `PUT InboundDomain` (the API refuses it without an MX, err 610).
7. Verify loop: `verifyDkim` + `verifyReturnPath` once a minute for 15 minutes, storing
   `dkim_state`/`rp_state` and `last_verify`. States refresh on `update_mail_domain` / "Verify
   now" (single pass).

## Inbound (`/hook/<domain>`, handlers in `internal/web/mail.go`, logic in `internal/mailbridge`)

1. Auth → 401 on failure. 2. JSON decode (limit) → 400; `MessageID` empty → 400.
3. Envelope recipient: `OriginalRecipient`, else first `ToFull`; lowercase; its domain must equal
   `<domain>` from the path → 403 (stops Postmark's retries; it is our config error).
4. Dedupe `sha256(MessageID|recipient)`: present → `deduped++`, 200.
5. Message bytes: `RawEmail` when it parses (plain RFC 822 first — verified live; base64 fallback,
   branch logged), else a deterministic rebuild from the JSON fields (ported
   `gopostmarkinbound/mime.go buildMIME`; DKIM of a rebuilt message cannot verify — counted as
   `fallbacks`). Both branches carry Postmark's `X-Spam-*`/`Received-SPF` headers as they arrive.
6. LMTP to the per-domain `lmtp_addr` or the global target: 250 → 200 (`delivered++`),
   4xx → 503 (Postmark retries; nothing stored), 5xx → 403 (`rejected++`; `mailbox not found`
   and others map the same way — gopmstall maps both to 403).
7. Success: insert the dedupe key, `recv++/delivered++/last_inbound` in one transaction.

Spam handling: none — Postmark's verdict stays in the message headers (`InboundSpamThreshold`
blocks before the webhook anyway), the LMTP server's own filter decides. Documented, like gopmstall
Spike 4's outcome.

## Events (`/events/<domain>`)

Store the payload (bounded); then, for a `Bounce` with `From`: build an RFC 3464 DSN
(`From: MAILER-DAEMON@<domain>`, human part, `message/delivery-status` per recipient, the bounce
`Content` as `message/rfc822` when present) and LMTP it, deduped on the bounce ID. `From` whose
localpart is `mailer-daemon` is stored but never answered (loop guard). Everything else — spam
complaints, SMTP-API errors, open/click — is stored only.

## LMTP client (`internal/mailbridge/lmtp.go`)

`github.com/emersion/go-smtp` client (`NewClientLMTP`, `Hello`, optional `StartTLS`, optional
`Auth` (PLAIN or LOGIN), `Mail`/`Rcpt`/`Data`), net.Dialer deadline. The only new dependency;
hand-rolling reply parsing/STARTTLS/AUTH is ~150 lines of known bug surface.
Envelope: inbound sender = the webhook `From` address (fall back `<>`); DSN envelope `MAILER-DAEMON@<domain>`.

## UI

- `/mail` (new `mail.html`): needs Cloudflare configured. Rows per domain: webhook paths, verify
  states (`Verify now`), DNS notes, counters, last inbound, LMTP override fieldset, Remove
  (`hx-confirm`). Provision form (domain + adopt checkbox). Recent events table. One-time
  credential display block right after provisioning (flash), path-only afterwards.
- Settings gains a "Mail bridge" fieldset (`POST /settings/mail`): account token (write-only,
  blank keeps), LMTP host:port, TLS checkbox, auth user/password (write-only, blank keeps).
- Help hints in `help.go` for both pages.

## MCP (0.15.0)

`list_mail_domains`, `get_mail_domain`, `create_mail_domain` (`domain`, `adopt`; optional
`hook_user`/`hook_pass` override — so MCP callers never depend on a shown-once password),
`update_mail_domain` (re-push + re-verify + set the LMTP override), `delete_mail_domain`,
`list_mail_events`. Mutations reuse the UI handlers via `mcpRun` (audit for free). New
`skills/servanago-mail/SKILL.md`; docs/mcp.md, llms.txt (UI + MCP lists), README feature line,
ROADMAP row.