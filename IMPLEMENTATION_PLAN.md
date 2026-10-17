# M5: Apply v2 (one pass)

Scope decisions (ponytail):
- **Reconciler**: startup convergence of the only managed state (Caddy config) already exists
  (`apply.Start`); M5 adds the missing half: last-known-good restore and system audit events.
- **Last-known-good**: after every successful `caddy.Load`, the full rendered JSON is written to
  `<DATA_DIR>/caddy-last-good.json` (atomic rename). Startup with rejected DB config loads it
  before falling back to bootstrap-only; the banner keeps explaining the DB problem.
- **Audit events**: apply writes `config.changed`, `config.rejected`, `config.restored`,
  `config.bootstrapped` rows (actor `system`, target `caddy`) — the Audit page shows them.
- **Service status / journald**: helper gains typed `unit-status` and `unit-logs` actions with
  real seam implementations, so M6 (Node units) can serve them immediately. No UI column yet:
  no site has a unit until M6 — an empty column is noise, not a feature.
- No schema change: no `002_*.sql`, no compatibility work.

## Stage 1: LKG + apply audit events
**Tests**: apply_test — restore from LKG on broken DB render; bootstrap when no LKG; Mutate
success/failure audit rows.
**Status**: In Progress

## Stage 2: helper unit-status + unit-logs
**Tests**: fake seam + real seam shape tests.
**Status**: Not Started

## Stage 3: docs + gate
**Status**: Not Started