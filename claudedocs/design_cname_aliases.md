# Design: CNAME records for site aliases

Requirements: `claudedocs/requirements_cname_aliases.md`. Built in one pass (one branch, one `make check`, no stages).

## Summary

Aliases (`Hostnames[1:]`) and the ml host get one owned CNAME to the primary hostname instead of A + AAAA. The primary keeps A/AAAA. The change lives in four places: migration 012, `store` (a constant), `cfdns` (CNAME support), `dnssync.run` (which families a name wants). Nothing in the web layer changes except tests, docs and what the rows display.

## Data: migration `012_dns_cname.sql`

`dns_records.family` has `CHECK (family IN ('A','AAAA'))`; SQLite cannot alter a CHECK, so rebuild the table, following 011 (migrate() already applies pending files with `foreign_keys` OFF):

```sql
CREATE TABLE dns_records_new ( ...same columns as 001...,
  family TEXT NOT NULL DEFAULT 'A' CHECK (family IN ('A','AAAA','CNAME')),
  PRIMARY KEY (hostname, family));
INSERT INTO dns_records_new SELECT hostname, site_id, family, cf_record_id, content, owned, state, error, synced_at FROM dns_records;
DROP TABLE dns_records;
ALTER TABLE dns_records_new RENAME TO dns_records;
```

- Nothing references `dns_records`, and it has no index besides the PK, so the rebuild is self-contained.
- `ui_dns_record` keeps its A/AAAA CHECK: the UI host is never an alias.
- `user_version` becomes 12: bump the hard-coded `12`/`11` in `TestMigrationsIdempotent` (`store_test.go:41`).
- Rehearse through a real Store on a copy of bee's DB (`DATA_DIR=copy bin/servanago`), never the sqlite CLI. Per-table counts before/after, `foreign_key_check`, `integrity_check`.
- Add a guard like `TestMigrationRebuildKeepsChildRows`: seed pre-012 `dns_records` rows, migrate, assert the rows survive.

## `store`

- `const FamilyCNAME = "CNAME"` beside `FamilyA`/`FamilyAAAA` (`models.go:119`). `DNSRecord.Family` comment updated.
- `ListDNS`/`ListSiteDNS` order by `family`: alphabetical `A < AAAA < CNAME` is already the order wanted. No query changes.

## `cfdns`

- `FamilyCNAME`; `checkFamily` accepts it (message: "want A, AAAA or CNAME").
- `FindRecord`: `listType` gains `dns.RecordListParamsTypeCNAME`. Returns `Content` = the target as Cloudflare stores it.
- `recordBody(name, family, content)`: CNAME case builds `dns.CNAMERecordParam` (type CNAME, TTL 1, `Proxied: false`, same `ManagedComment`). Parameter `ip` is renamed `content`. Confirm the param type exists in cloudflare-go v7.13 while writing; CNAME needs only `content`, so the typed decode that drops `priority`/`data` is irrelevant here.
- `CreateRecord`/`UpdateRecord`/`DeleteRecord` signatures unchanged apart from the rename.

## `dnssync.run`

Names keep today's order: `Hostnames` (primary first), then the ml host. Per name:

- **Primary** (`name == rt.Hostnames[0]`): wants A and AAAA as today and no CNAME.
- **Alias or ml host**: wants CNAME = primary FQDN and no A/AAAA. `record_ip`/`record_ip6` and domain default IPs are not read for it.

Both cases are the same shape, "this name wants family set W; every other family of the three is a blocker to clear before W is written". One helper:

```go
// clearOthers removes what would block the wanted families at name: the records of the families not wanted.
// An owned one (row id matches the Cloudflare record) is deleted and its row dropped; with takeOver any is.
// A foreign one stays and is returned as a blocker message ("example.com has an A record 1.2.3.4 ...").
func (s *Syncer) clearOthers(ctx, zone, name string, unwanted []string, takeOver bool) (blocker string, err error)
```

Per unwanted family: `FindRecord`; none found and a row exists → drop the row; found and (`row.Owned && row.CFRecordID == found.ID` or `takeOver`) → `DeleteRecord`, drop the row; found otherwise → blocker. This replaces `syncFamily`'s `want == ""` branch for these names, so `syncFamily` loses that branch's "adopted record left alone" case: the adopted record is now a visible blocker instead of a silent drop (the old behaviour hid it because nothing conflicted).

Then for each wanted family, `step` as today with content = IP or primary FQDN. Differences in `step`:

- Content comparison for CNAME uses `strings.EqualFold` (Cloudflare lowercases, strips the trailing dot).
- If `clearOthers` returned a blocker or a delete error, the wanted family's row is written as `conflict` (blocker) or `error` (delete failed) with the message, and `step` is skipped. Rows for the deleted records are already gone, so a failed CNAME create after a good delete leaves no stale row; the next reconcile finds nothing at the name and creates it.
- Warning (decision 6): after a CNAME `synced`, if the primary has neither an A nor an AAAA row in `dns_records` (`GetDNS(primary, …)` both `sql.ErrNoRows`), set `Error = "target <primary> has no record managed by ServanaGo"` and keep `State = "synced"`. The primary is processed first, so its rows are current.

Primary promotion (alias becomes `Hostnames[0]`): the old CNAME is in `unwanted` for the new primary, so it is deleted and A/AAAA created. The demoted primary's A/AAAA are in `unwanted` for the new alias and deleted, then its CNAME is created. A primary change also changes every other CNAME's content, handled by `step`'s `UpdateRecord` path (owned, content differs).

`prune`, `Remove`, `deleteSite`/`removeRecord`, `dnsTargetOf` work on `CFRecordID` + zone and are type-agnostic; add a test that deleting a site with an owned CNAME alias removes it (`delete_dns`).

`families` stays `A, AAAA` for the UI host (`ReconcileHost`) and `web/host.go`/`dnsadmin.go` loops; those are about the UI host rows only and need no change.

## Startup conversion

`Reconcile` runs at startup for every site, so the first start after the upgrade converts every alias and ml host on bee, v1 and timmy in one pass. Per name: three Cloudflare list calls, up to two deletes, one create. Cost is roughly one extra list call per name compared with today. The name does not resolve between the delete and the create (seconds).

Known limits, shown verbatim as `error`/`conflict` and never fixed automatically:
- A non-address record (TXT, MX, ...) at an alias name blocks the CNAME at Cloudflare; the Cloudflare error text surfaces on the row.
- A foreign A/AAAA at an alias name is a `conflict` until the admin removes it or runs take over.

## Tests (all in the same change)

`dnssync_test.go` with `cftest.Fake` (look records up by name, never `Records()[0]`; snapshot `Writes()` deltas):

1. alias + gated site: A/AAAA on primary, CNAME on alias and ml, nothing else.
2. upgrade case: seeded owned A/AAAA on alias and ml → one reconcile → CNAMEs, old rows gone, no records left behind.
3. foreign A at alias: `conflict`, record untouched; `TakeOver` replaces it.
4. adopted (not owned) A/AAAA row on an alias: `conflict`.
5. CNAME create fails after a successful delete → `error` row, no A rows, next reconcile succeeds (`Fake` fail switch).
6. promote alias to primary and demote: records swap, no leftovers.
7. primary IP change touches only the primary's records.
8. primary without a domain, alias with one: CNAME `synced` with the warning text.
9. apex alias CNAME written; cross-zone alias works.
10. site delete with `delete_dns` removes the owned CNAME; alias removal prunes it.

Other:
- `cftest.Fake` must honor the posted record type on create/update (verify; `Add` already takes `Type`) and reject a CNAME create while another record exists at the name (and an A create while a CNAME exists), as Cloudflare does; without that, the delete-before-create order is untested.
- `cfdns/records_test.go`: CNAME find/create/update, case/trailing-dot content.
- Store: migration 012 guard and `TestMigrationsIdempotent` version.
- Web/MCP: `TestMCPDnsTools` and the site DNS-row tests that assume alias rows are A/AAAA are updated; `get_site` dns rows show `family: CNAME`.
- e2e: grep for specs asserting alias A/AAAA rows (`dns_records`/"A record" text) and adjust.

## Docs and release bookkeeping

`docs/sites.md` (aliases are CNAMEs; why a non-address record at an alias blocks), `docs/mcp.md`, `llms.txt`, README feature line, `docs/ROADMAP.md`, `skills/servanago-sites/SKILL.md` ("since X.Y.Z"). No version bump, tag or deploy until asked; the release notes must say the first start converts all aliases.

## Risks

- Brief resolution gap per alias on upgrade (accepted, requirements N3).
- Rollback to an older binary: the old code reads `family IN (A, AAAA)` rows only, ignores CNAME rows, and on its next reconcile finds a foreign CNAME at the alias and reports `conflict`. State this in the release notes; the CHECK on 012 is not reversible by an older binary, same as every migration.
- `Hostnames[0]` must be the primary everywhere `run` assumes it (it is what `Handler.Primary` and `buildRows` use); a test asserts the DNS primary equals the site's primary after a hostname reorder.
