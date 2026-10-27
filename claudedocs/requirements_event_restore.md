# Requirements: undo one audit event (event restore)

Date: 2026-10-27. Status: requirements settled, design not started.

Every mutating change in the audit log (the "RUD" events: entity.created / updated /
deleted, including ones made through MCP) must be undoable: undoing an event puts the
system back to the state just before that event.

## Decisions settled this session

- **Undo one event**, not point-in-time rollback. One event, one snapshot, one undo.
- **Scope: all mutating events** — sites (row, hostnames, grants, attached snippets),
  domains, snippets themselves, admin users, settings, DNS record rows.
- **Undo of a delete restores DB state only**: re-create row + hostnames + grants + DNS
  rows, re-apply Caddy and runtime units the way a save does. Webroot files are never
  touched (Servanago never deletes site files). DNS restoration goes through the normal
  reconcile path, re-creating only records the site owns.
- **Surfaces: Audit page button + one MCP tool** calling the same path. MCP-made
  mutations already audit with actor "mcp token" (mcpRun reuses the UI handlers), so
  they are covered by the same snapshots for free.
- **Later changes to the same entity: warn, allow overwrite.** The confirm step names
  the newer events; proceeding overwrites with the snapshot; nothing is hidden.
- Storage: a snapshot keyed by audit event id, trimmed when its audit row is trimmed
  (audit rows are capped at 10000). Schema is a design decision, not settled here.

## Functional requirements

1. **Snapshot capture.** Every mutating action stores the full before-state of the
   entity it touches, in the same DB transaction as the mutation. A failed or rolled
   back mutation leaves no snapshot behind. Existing pre-load points to reuse:
   `updateSite`/`updateDomain` already load `cur`; `deleteSite` already captures `deleted`
   (internal/web/siteedit.go:101) and `dnsTargetOf` already collects the rows.
2. **Undo semantics per action class.**
   - `*.created` — undo performs that entity's normal delete (a site: today's
     `deleteSite` path, runtime teardown included).
   - `*.updated` — undo re-applies the before-state through the existing mutate paths,
     with full validation. A snapshot that no longer validates refuses undo (fail closed).
   - `*.deleted` — undo re-creates the entity as it was, identifiers included
     (site slug). Undo is refused with a clear error when the slug/name was taken
     since (slug or domain name reused).
3. **DNS side effects belong to the event.** Record removals that have no audited event
   today (the `delete_dns` checkbox of site delete, cleared IP fields on edit) are part
   of the snapshot: the restored rows state is authoritative, and Cloudflare re-sync
   happens only through the normal reconcile, never by replaying raw API calls.
4. **Undo is audited and undoable.** Undo writes `event.restored` (target names the
   undone event id) and carries its own snapshot, so an undo can be undone by undoing
   it: reverse chaining falls out for free.
5. **Same apply discipline as every mutation:** validate spec, SQLite tx, host
   artifacts via the helper, full Caddy JSON render, `caddy.Load`, commit; roll back on
   failure. Caddy config is never edited piecemeal.
6. **No snapshot, no undo.** When the snapshot is gone (event older than the audit
   cap), the undo button is disabled with a plain reason. Never a partial restore.
7. **Actors.** Undo records the acting actor (username, or "mcp token"). Undoing an
   MCP-made mutation works identically from the UI; the MCP tool runs the same
   handler path as the button.
8. **Secrets.** Snapshots must never contain plaintext secrets: only sealed blobs
   (secretbox) and password hashes. Restoring restores the same opaque values.
9. **Confirm + re-auth.** Undo asks for re-auth (existing `reauth` convention) and
   confirms like other destructive steps; the conflict warning (later events naming the
   same entity) appears in the confirm text.

## Acceptance criteria

- Delete a site, undo the `site.deleted` event: site, hostnames, grants and DNS rows
  are back, Caddy serves the hostname again, webroot files never left disk, unit files
  re-created. If the slug was reused in between, undo is refused with a clear error.
- Rename a site's hostnames, undo the `site.updated` event: previous hostnames are
  back; the Cloudflare rows converge through the normal reconcile.
- Undo an `event.restored`: the previous state returns (undo of undo works).
- Undo a `site.created`: the site goes through today's delete path (confirm included).
- An MCP mutation followed by an MCP undo call restores the same state and both
  events appear in the audit log with actor "mcp token".
- An event without a snapshot shows a disabled undo and the reason.
- All the above covered by store/web tests against in-memory SQLite + fake seams, plus
  an MCP test (`mcpRun` the same handler) and e2e for the button path.

## Open questions

- Password changes: undoing `user.password_changed` re-activates the previous hash —
  is that wanted, or should users events be excluded from undo?
- Undo for grant add/remove rows (they are inside site.updated too) — separate undo
  buttons, or covered only via the site event?
- Does the Audit page need pagination/search before this (ListAudit is limited to 200
  rows for the page)?

## Next step

/design: snapshot table schema, capture points per handler, restore re-apply flow per
entity, where the MCP tool sits (name matches the `restore_` verb — no toolLike regex
change needed).