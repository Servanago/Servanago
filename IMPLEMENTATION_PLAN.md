# M4: Privileged helper

Helper = same binary, `servanago helper` subcommand, long-running root daemon on
`/run/servanago/helper.sock` (0660 root:servanago). Auth: `SO_PEERCRED` uid must be root or the
`servanago` user. Protocol: one newline-delimited JSON request, one JSON response, then close.
Closed set of typed actions, no free-form strings; helpers re-validate everything; unit files
written only from the helper's embedded template as `servanago-<slug>.service`.

## Stage 1: validators + action types + fuzz
**Goal**: `internal/helper/types.go` — Request/Response, `unit-install` Spec `{slug}`, validators
(slug `^[a-z][a-z0-9-]{1,31}$`, unit name built only as `servanago-<slug>.service`).
**Success Criteria**: table tests + `testing.F` fuzz over validators (NUL, over-long, traversal, unit-file injection chars).
**Tests**: `internal/helper/types_test.go`.
**Status**: In Progress

## Stage 2: daemon + SO_PEERCRED + protocol
**Goal**: `internal/helper/server.go` — listen on unix socket, per-conn handler: credential check
(pure function over a peer struct so tests fake uids), decode with scanner cap, dispatch, respond, close.
`ping` action for the no-op path; `unit-install` action shell.
**Success Criteria**: tests dial a real temp socket (no SO_PEERCRED faking: auth fn unit-tested separately).
**Tests**: `internal/helper/server_test.go`.
**Status**: Not Started

## Stage 3: unit-install with fake systemd/filesystem seam
**Goal**: helper writes its own template to `/etc/systemd/system/servanago-<slug>.service`,
`systemd-analyze verify`, `daemon-reload`, `enable` — behind a seam; refuses symlink targets, never writes outside the unit name.
**Success Criteria**: fake seam tests pass; fuzz proves no slug escapes the fixed name.
**Status**: Not Started

## Stage 4: subcommand + packaging + client
**Goal**: `servanago helper` wired in main; `internal/helper/client.go` for M5 to call; packaging ships
`servanago-helper.service` (root, RuntimeDirectory=servanago) and postinst enables it.
**Tests**: packaging test covers helper unit; client round-trip covered in stage 2 tests.
**Status**: Not Started

## Stage 5: docs + gate
**Goal**: ROADMAP M4 done, README helper note, plan deleted, `make check`.
**Status**: Not Started

## Notes
- The unit template body is a placeholder (`Type=oneshot`, `ExecStart=/bin/true`): M6 (Node provider)
  defines the real ExecStart/user/env fields. Wiring helper calls into the control plane also waits for M5.
- No SQLite, no audit rows: the helper logs each action to journald via slog.