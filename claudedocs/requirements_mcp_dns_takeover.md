# Requirements: MCP DNS takeover + visibility (v0.10)

Goal: an agent over MCP can do everything the web UI can around a site's DNS
record IPs — site scope, plus the domain defaults that feed them.

## Current state (verified in code)

- Setting IPs: MCP `create_site` / `update_site` already take `record_ip` +
  `record_ip6` (`internal/web/mcp.go:79-80`), same apply path as the UI form.
- Claiming (takeover of a conflicting, unowned Cloudflare record): web UI only.
  Buttons `POST /sites/{id}/dns/takeover` and `/host/dns/takeover`
  (`web.go:234,240`), handler `dnsAction(..., Syncer.TakeOver)`
  (`siteedit.go:187`). Normal sync leaves such records in state `conflict`;
  only TakeOver overwrites and marks owned (`dnssync/dnssync.go:45,164-166`).
- Domain defaults: `updateDomain` (`domains.go:136-198`) edits
  `default_ip`/`default_ip6`/`cert_mode` (+zone) and touches no DNS records
  (`domains.go:134-135`); sites converge via Resync
  (`POST /sites/{id}/dns/resync` → Reconcile, `web.go:239`). `list_domains`
  already reads all three fields (`mcp.go:297`).
- Reading back: `siteView` omits `record_ip` and all DNS state (`mcp.go:204-220`).

## Functional requirements

1. **`take_dns {id}` write tool.** Same handler as the UI button
   (`s.takeOverDNS`), therefore same validation, `Syncer.TakeOver` semantics,
   audit row `site.dns_taken_over` with actor `mcp token`. Idempotent: takeover
   on synced rows is a no-op (record unchanged unless content differs). Result:
   the refreshed record list (same shape as FR2) — no second read needed.
2. **DNS visibility in `get_site`.** `siteView` gains `record_ip`,
   `record_ip6` (omitempty) and per-row DNS state for every hostname the site
   answers on, including `ml.<primary>`: `dns: [{hostname, family, state,
   content, error?}]` (`state` = pending | synced | error | conflict, as stored).
   Read tools only; no secrets (states/errors are non-secret).
3. Guard test in the MCP tool-surface test (`TestMCPSnippets` style): a site
   with `record_ip` set survives `update_site` without that field (already
   handled by `formOf`, but pin it now that it is part of the contract).
4. **`resync_dns {id}` write tool.** Same handler as `POST /sites/{id}/dns/resync`
   (`dnsAction(.., Reconcile)`). Needed because domain-default changes never
   touch existing records (`domains.go:134-135`): without this the agent cannot
   converge sites whose `record_ip` is empty after an `update_domain`.
5. **`update_domain {id, default_ip, default_ip6, cert_mode?}` write tool.**
   Runs the same handler as the UI's `PUT /domains/{id}` (`updateDomain`,
   `domains.go:136-198`): validates via `config.ValidateIP/ValidateIP6`, refuses
   `wildcard` without Cloudflare, audited `domain.updated`. `cert_mode` keeps
   the stored value when omitted (overlay onto current, like `update_site`).
   Name and zone stay web-only. `list_domains` already returns `default_ip`,
   `default_ip6`, `cert_mode` (`mcp.go:297`) — no read-side work.
6. **`create_domain {name, default_ip, default_ip6?, cert_mode?}` write tool.**
   Same handler as the UI's `POST /domains` (`addDomain`, `domains.go:78-132`):
   validates the name (`config.ValidateDomain`), looks the zone up live
   (`CF.ZoneID`), refuses `wildcard` without Cloudflare, defaults `cert_mode`
   wildcard/per_host by `dnsOn()` like the form, audited `domain.added`.
   Completes the headless flow: an agent granted `create_site` can otherwise
   not put a hostname under a Cloudflare zone.

## Non-goals (this round)

- Host-row takeover/resync (`POST /host/dns/*` for `SERVANAGO_HOST`): web only.
- Domain name or zone changes via MCP.

## Acceptance criteria

- Site whose Cloudflare A record points elsewhere, unowned: `update_site` with
  `record_ip` leaves state `conflict`; `get_site` reports it (hostname, content
  "elsewhere", state conflict, error string intact).
- `take_dns` flips it to `synced`, content now the wanted IP, row owned; audit
  row exists with actor `mcp token`'s action `site.dns_taken_over`.
- `take_dns` again: no Cloudflare write, still `synced` (idempotent).
- `resync_dns` on a conflict row changes nothing (Reconcile keeps `conflict`);
  on a stale-but-matching unowned row it adopts without a Cloudflare write.
- `update_domain` with a bad IPv6 answers 422 with "default IPv6: …"; a valid
  change persists, audit row `domain.updated`, and no Cloudflare write happens.
- Site with empty `record_ip` under that domain: still stale after
  `update_domain` until `resync_dns` (records are not auto-touched — UI parity).
- Gated site: `ml.<primary>` row visible in `get_site`.
- `create_domain` with an unseeable zone name answers 422 with the `CF.ZoneID`
  error text; a valid create persists, audit row `domain.added`, then
  `create_site` with a hostname under it resolves the new domain.

Open questions: none. (Resolved, no decision needed: `take_dns`/`resync_dns`
on a site whose hostnames have no domain rows 200s with an empty result — the
shared handler (`Syncer.run`) skips domain-less names and errors on nothing;
UI parity.)