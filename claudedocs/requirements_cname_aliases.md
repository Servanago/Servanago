# Requirements: CNAME records for site aliases

Status: requirements only (2026-11-24). Next: `/sc:design`.

## Goal

Alias hostnames (`Hostnames[1:]`) and the magic-link host (`ml.<primary>`) get one Cloudflare CNAME pointing at the primary hostname instead of their own A + AAAA pair. The primary stays the single IP source of truth.

## Decisions (settled with the user)

1. Scope: aliases AND `ml.<primary>`. The primary keeps A/AAAA.
2. Existing sites: auto-convert on the next reconcile. Owned A/AAAA on an alias or ml host is deleted and replaced by the CNAME. Adopted (not owned) A/AAAA stay untouched and show as `conflict`, as today.
3. No fallback: an alias is always a CNAME. If the primary has no A/AAAA row that ServanaGo manages (no domain, HTTP-01, record missing), the alias row is still written and flagged with a warning ("target has no managed record"), not skipped and not turned into A/AAAA.

4. Row shape: `family` gains a third value `CNAME` (one row per alias/ml name, content = primary FQDN). Ordering A, AAAA, CNAME; family loops skip A/AAAA for CNAME names.
5. Conversion order: delete owned A/AAAA, then create the CNAME; a failed step keeps the row in `error` and the next reconcile resumes. No in-place type PATCH.
6. Warning storage: state stays `synced`; the existing `error` column carries the "target has no managed record" text, shown as a notice.

## Functional requirements

- F1. `dnssync.run` writes, for each alias and ml name that resolves to a domain, one CNAME with content = primary FQDN. No A/AAAA are wanted for it.
- F2. Owned/adopt/conflict/takeOver rules carry over unchanged: owned CNAME is updated/deleted; an existing CNAME with the same target is adopted; a different record at the name is a `conflict`; `TakeOver` overwrites.
- F3. Conversion: when an alias has owned A/AAAA rows, delete those at Cloudflare (a CNAME cannot share a name with other records) before creating the CNAME. A failed delete keeps the row, records `error`, and retries next reconcile (same as `prune`).
- F4. Reverse: if an alias is promoted to primary, its CNAME is removed and A/AAAA are created. Removing an alias or the site deletes the owned CNAME (`removeRecord`, `prune`, `delete_dns` path).
- F5. Primary change (reorder hostnames): all CNAME contents are rewritten to the new primary.
- F6. Per-site `record_ip` / `record_ip6` and domain default IPs apply to the primary only; aliases ignore them.
- F7. Zone apex alias: CNAME is written anyway (Cloudflare flattens at the apex). Cross-zone alias (alias in a different managed zone than the primary) works: content is the primary FQDN.
- F8. Proxied flag: the CNAME copies whatever the current A/AAAA creation uses (no new setting).
- F9. UI: site list/edit DNS rows show type CNAME and target; the broken-target warning appears there. `/dns` pages (DNS CRUD) list CNAME rows as owned by the site; MCP `get_site` dns rows show family `CNAME`.
- F10. Health/`dnsTargetOf`, import (`servanago import`), and MCP DNS tools (`takeover`, record tools) handle the new row type.

## Non-functional

- N1. Schema change is a new `NNN_*.sql` migration, never an edit of `001`/`002`; rehearse through a real Store on a copy of bee's DB (FK-off rebuild gotcha). The `family` column and any CHECK on it must admit CNAME.
- N2. A DNS failure never reverts a site (unchanged).
- N3. Brief resolution gap during conversion is accepted (A/AAAA deleted, then CNAME created).
- N4. Tests: golden/fake `cftest.Fake` coverage for create, convert, adopt, conflict, takeOver, promote, remove, broken-target warning; real Cloudflare never in tests.
- N5. Docs: `docs/sites.md`, `docs/mcp.md`, `llms.txt`, README feature line, ROADMAP, `skills/servanago-sites/SKILL.md` ("since X.Y.Z").

## Acceptance criteria

- A site with primary `a.example.com`, alias `b.example.com`, gate on: Cloudflare ends with A+AAAA for `a`, CNAME `b → a`, CNAME `ml.a → a`; nothing else.
- Upgrading a v1-like DB with owned A/AAAA on `b` and `ml.a`: after one reconcile they are CNAMEs, rows show `synced`, no orphan A/AAAA remain.
- Alias with a foreign A record: `conflict` row, record untouched; `TakeOver` replaces it.
- Primary without a managed record: alias row `synced` (CNAME exists) plus visible warning.
- Changing the primary's IP touches only the primary's records.

## Open for design (technical, not user decisions)

1. `cfdns` client: `CreateRecord/UpdateRecord/FindRecord` take an A/AAAA family and an IP; they need a CNAME variant. CNAME needs only `content`, so the typed SDK path should do (verify against cloudflare-go v7.13).
2. Warning copy for a primary with no managed record (primary without a domain, alias with one).
