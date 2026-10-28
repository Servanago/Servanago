# Design: Cloudflare DNS CRUD

Requirements: `claudedocs/requirements_next_features.md` §3 (settled 2026-10-28). No implementation here; build plan at the end.

## Shape

DNS CRUD touches **Cloudflare only**. No Caddy render, no helper, no `Apply` pipeline, **no new SQLite tables** — the zone and record IDs live in Cloudflare; everything except the audit log is read live from the API per page load. No schema migration, `user_version` unchanged.

One guard against API hammering: no cache. Zone list is one paginated call; record list a few. Cloudflare allows 1200 req/5 min per token, and the page is admin-only. (ponytail: add a TTL cache only if a user hits it hourly.)

## Packages touched

| Package | Change |
|---|---|
| `internal/cfdns` | Four new methods on the existing `Client` (token unchanged: `CLOUDFLARE_API_TOKEN`) |
| `internal/cfdns/cftest` | Fake gains zone-list (no name filter), pagination, TTL round-trip |
| `internal/web/dnsadmin.go` (new) | 5 handlers + 2 templates |
| `internal/web/mcp.go` (+`mcp.go` additions) | 5 MCP thin wrappers |
| `internal/web/web.go` | 5 routes, nav entry |
| skills/docs | SKILL.md tool names, `docs/mcp.md`, `llms.txt`, README line, help hints |

## cfdns API additions

```go
type Zone struct{ ID, Name, Status string }

// ListZones returns every zone the token can see (paginated, per_page=50, server-side loop).
func (c *Client) ListZones(ctx context.Context) ([]Zone, error)

// ListRecords returns a zone's records of every type (paginated, per_page=100),
// sorted type, then name. TTL/proxied/comment included.
func (c *Client) ListRecords(ctx context.Context, zoneID string) ([]FullRecord, error)

type FullRecord struct{ ID, Name, Type, Content string; TTL int; Proxied bool; Comment string }

// CreateRecordFull / UpdateRecordFull / DeleteRecordFull: like the A/AAAA-only
// versions but for any SDK-union type, taking FullRecord bodies.
```

The writable-type set is **the eight the SDK union exposes cheaply: A, AAAA, CNAME, TXT, MX, SRV, CAA, NS**. Exotic types (TLSA, DS, SVCB, …) are listed read-only in v1; the API rejects them with "type X is read-only in ServanaGo". They are rare on a web runtime host, and the union plumbing per type is the only thing between here and full Cloudflare parity — add on demand.

## Web UI

Routes (matching the `snippets`/`domains` handler style, all `s.protected`, htmx row-swap, `fail()` for errors, `hx-confirm` on deletes):

```
GET   /dns                          zone list: name, status, link
GET   /dns/zones/{zid}              records table (type/name/content/ttl/proxied/comment), add form
POST  /dns/zones/{zid}/records      create
PUT   /dns/zones/{zid}/records/{rid} update
DELETE /dns/zones/{zid}/records/{rid} delete
```

- Names are posted **zone-relative** (`cdn`, `@`, `*.static`) — ServanaGo appends the zone where it posts absolute to the API, one writer, no double guessing.
- Typed form fields per type: A/AAAA (address via `config.ValidateIP`/`ValidateIP6`), CNAME/TXT/NS (content), MX (mail server + priority), SRV (priority/weight/port/target), CAA (flags/tag/value). TTL numeric or 1 (Auto); proxied checkbox only for the CF-proxyable types (A, AAAA, CNAME); comment free text.
- **Managed badge (informational, per Brian's "full independent view" answer):** a row gets the badge when `Comment == "managed by servanago"` or its CF record id appears in a `dns_records` row (or the UI-host rows). Edits are never refused; the badge only warns that dnsync may rewrite/re-add this exact row at the next site save or startup. No dnssync code changes.
- Deleted-row behaviour is likewise unguarded: deleting a managed A/AAAA re-appears on the next reconcile. The audit log records who deleted what.
- No reauth: consistent with the snippets page (mutations audited, cookie CSRF applies).
- Zone list is plain; `ErrZoneNotFound`-class API failures surface as `fail()` text, never silent.

### Page layout (impeccable /layout review, 2026-10-28)

Mode: Operate. The incumbent world is dark `--sg-*` Pico-mapped panels inside the sidebar shell; the DNS pages reuse it and add no new CSS beyond two small utilities. Structural decisions:

- **Zone page reading order** (matches `snippets.html`): crumb `DNS / <zone>` (`.crumb`), table article (the primary surface), add-record article last. Zones list page: `page-head` with title + search, zones table (name, status, records link). Status uses the neutral `.tune` pill, not a status color — a pending zone is not an error.
- **Record table is 5 columns, not 6**: type, name (monospace), content (monospace, wraps; **comment renders under it as muted `small`**, never its own column), TTL, actions. Proxied renders as the incumbent dot in the type/name cell (`dot` amber/green) — this keeps the ≤640 px squeeze (`overflow-wrap: anywhere` rule) to five squeezeable columns and puts related facts together.
- **Managed badge = existing `.tune` neutral pill** after the record name; no new color token. The badge's meaning needs a help hint (`dns_managed`) bound next to the table, per the `help.go` rule.
- **Add/edit form**: one type `<select>` + one fieldset whose fields swap server-side via htmx (`GET /dns/zones/{zid}/form?type=MX` swaps `#record-fields`) — the same server-driven swap the site form uses, no client JS. Fieldsets: A/AAAA (address), CNAME (target), TXT (textarea), NS (nameserver), MX (mail target + priority), SRV (target/priority/weight/port), CAA (flags/tag/value) + shared TTL (Auto = 1 as `selected`), proxied (only A/AAAA/CNAME), comment. Extra fields posted for a different type are rejected, not silently dropped. Row edit reuses the form prefilled in a `details` row expansion (the `edit-snippet` pattern).
- **Zone list filter**: server-side `?name=` substring filter with an htmx search input (the `ref-controls` search pattern) — an account token can see hundreds of zones and the page must not render them all.
- **Record list paging**: server-side page param (per_page=100) + "older/newer" links, same spirit as the logs page. Sorted type then name, as the cfdns method already orders.
- **Empty states**: the incumbent `.empty` dashed panel — "No zones the token can see" (token misconfigured) on /dns, "No records yet" below the table.
- Squint test, rhythm, and mobile behaviour cannot be rendered-verified at design time (no page exists); verification is a bounded pass during implementation after stage 2's templates render — one batched screenshot round, one fix batch, stop there.
- No new spacing values or components: `crumb`, `page-head`, `tune`, `empty`, `mini` cover everything; the only CSS addition is a monospace class for record content if `pre`-in-table feels heavy at implementation time.

## MCP tools

Five tools (verb regex already covers all):

| Tool | Args | Wraps |
|---|---|---|
| `list_dns_zones` | — | zones page |
| `list_dns_records` | `zone` (id or name) | records page |
| `create_dns_record` | zone, type, name, content, ttl?, proxied?, comment?, priority? (MX/SRV) | create handler |
| `update_dns_record` | zone, record id, same optional fields | update handler |
| `delete_dns_record` | zone, record id | delete handler |

Existing names (`resync_dns`, `take_dns`, `create_domain`, …) untouched. `mcpRun` needs one extension: paths now carry a `{zid}` before `{id}` (it currently `SetPathValue("id", …)` only) — add an optional zone-id parameter, set via `r.SetPathValue("zid", …)`; every existing call site keeps working. MCP writes audit as "mcp token" for free via `mcpRun`.

## Auditing

`s.audit(r, "dns_record.created", type+" "+name+" "+zone)` and `.updated` / `.deleted`. No before-snapshot (event-undo is a separate future feature; a CRUD mutation's before-state is one `ListRecords` away, acceptable).

## Test layering

- `internal/cfdns`: unit tests against `cftest.Fake` — zone pagination, list all types, create/update/delete round-trips, error paths (`FailWith`).
- `internal/web`: `newServer` + extended `cftest.Fake.Handler()` mounted as the API; badge logic (managed comment, stored id, UID rows), create validations per type, `hx-confirm` presence, full-page completeness assertions (`>Save</button>`, `</form>`) per the template-test rule.
- MCP: `mcpRun` round-trips for all five tools; fresh-struct decode per the `omitempty` gotcha.
- No Caddy integration tests — Caddy is untouched.

## Docs to update (repo rule)

`docs/mcp.md`, `llms.txt` (MCP read/write lists + status line), README feature line, `docs/ROADMAP.md` M10 line, `skills/servanago-dns/SKILL.md` ("since X.Y.Z" — next minor), help hints in `internal/web/help.go` (plain text, no `<`).

## Build stages

1. **cfdns + fake**: the four methods, `FullRecord`, `cftest` zone/pagination support. Verify: unit tests green, existing A/AAAA tests untouched.
2. **UI**: handlers, templates, routes, badge, help hints. Verify: web tests green, page-complete assertions.
3. **MCP**: five tools + `mcpRun` zone extension. Verify: MCP tests, skill SKILL.md updated, `TestAgentSkillsMatchTheMCPTools` green.
4. **Docs + gate**: mcp.md / llms.txt / README / ROADMAP; full `make check` (env-unset Cloudflare token variant per CLAUDE.md), then branch→main.

Each stage commits. No migration anywhere; live-DB copy procedure does not apply.