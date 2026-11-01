# Built-in updater: design

Requirements: `claudedocs/requirements_updater.md` (settled 2026-11-01). Status: design, nothing built.

## Facts this design rests on (checked in the code)

- Upgrades today: `prerm` stops both units on `upgrade` and leaves `/run/<unit>.was-active` markers; `postinst` starts the marked units (helper first). The helper is the process that would run `dpkg`, and `prerm` stops the helper. So the install cannot run inside a helper action: it needs a process outside the helper's cgroup.
- The helper already authorizes root and the `servanago` uid (`NewAuthorizer`), so `servanago update` run with sudo can use the same client.
- PHP jobs set the precedent: the helper starts fixed systemd units that run `servanago php-job ...` and report through a state file (`internal/phpbuild`).
- The PHP release check is the precedent for the check: weekly loop at start plus every 7 days (`RunPHPChecks`), result in `settings`, one mail per signature (`Notified`).
- The binary has **no version string** today. The version lives only in `packaging/DEBIAN/control` and the other release places.
- The sqlite `servanago.db` is WAL: a live copy is not consistent. Copy only after the units stop.

## Overview

```
 release script ──► latest.json + latest.json.sig + servanago_X_amd64.deb ──► GitHub release assets
                                   │
 web: RunUpdateChecks (weekly) ────┘ fetch + verify (display only, never trusted for install)
   │ Updates page / dashboard card / mail+ntfy / MCP check_update
   │
   └─ POST /updates/upgrade (re-auth, preflight) ─► helper action update-start {expect: "X"}
                                                       │ re-fetch + verify manifest itself
                                                       ▼
                                          systemd-run  servanago-upgrade.service  (root, own cgroup)
                                          `servanago update-job`  ── state: /var/lib/servanago-update/state.json
                                                       │ 1 stage previous .deb   2 download + verify new .deb
                                                       │ 3 stop units, copy DB   4 dpkg -i new   5 start, health
                                                       │ 6 on failure: dpkg -i previous, restore DB, start, health
                                                       ▼
                                          result.json ──► web at next start: audit event, clears file
```

## Components

### 1. `internal/buildinfo` (new, tiny)
`var Version = "dev"`, set by `-ldflags "-X .../buildinfo.Version=X.Y.Z"` in `make build` (from the `control` file) and in `build-deb.sh`. `dev` (source builds, tests) means the updater shows notices only and refuses to upgrade. Needed by the check, the helper and the job.

### 2. `internal/update` (new)
- `Manifest` (JSON, versioned `"schema":1`):
  ```json
  {"schema":1,"version":"0.18.0","released":"2026-11-01","notes_url":"https://github.com/Servanago/Servanago/releases/tag/v0.18.0",
   "min_upgrade_from":"0.5.0","schema_change":true,"breaking":false,
   "debs":{"amd64":{"url":"https://github.com/Servanago/Servanago/releases/download/v0.18.0/servanago_0.18.0_amd64.deb","sha256":"...","size":12345678}}}
  ```
- `Verify(manifestBytes, sig []byte) (Manifest, error)`: Ed25519 over the exact bytes (stdlib `crypto/ed25519`, no new dependency). Public keys are a compiled-in **list** (`keys.go`); any one may verify. Rotation = ship a release that carries old + new key, then sign with the new one. Signature file is base64.
- `Newer(running, candidate)`: semver compare; `dev` never newer.
- URL rule: `debs[*].url` must be `https://github.com/Servanago/Servanago/releases/download/v<version>/servanago_<version>_<arch>.deb`. Anything else is rejected, so a valid signature still cannot point the root downloader elsewhere.
- Fixed constants: `ManifestURL = https://github.com/Servanago/Servanago/releases/latest/download/latest.json` (+ `.sig`), and `ManifestAt(version)` for `releases/download/v<ver>/latest.json`.

### 3. Check (web)
- `internal/web/updatecheck.go`, modelled on `phpcheck.go`: `RunUpdateChecks(ctx)` weekly, immediate at start if stale, plus `POST /updates/check`.
- Fetch through the process's proxy-aware client; size cap 64 KiB; verify; store.
- Storage: **migration `009_update.sql`**: `settings.update_check INTEGER NOT NULL DEFAULT 1`, `update_check_json TEXT NOT NULL DEFAULT ''`, `update_checked_at INTEGER NOT NULL DEFAULT 0`. `SERVANAGO_UPDATE_CHECK=false` forces off and shows the toggle disabled with the reason. Bump `TestMigrationsIdempotent`'s `user_version`.
- Notice: when a newer version appears, send the mail/ntfy message once per version (`Notified` = version), through the same sender the PHP check uses. Audit `update.checked` (actor `system`) only when the result changes.
- Off or `dev`: no outbound call.

### 4. Updates page (web)
`/updates` (nav entry under Settings or Help): running version, latest version, notes link, schema/breaking badges, last check time, **Check now**, **Upgrade to X** (password field, `ack` checkbox when `schema_change || breaking`), a progress panel that polls `state.json` while a job runs. `s.upgradeBusy(ctx)` refuses (with the reason shown, button disabled) when: a PHP build unit/state is active, a backup run is running, a scan run is running, or `state.json` says an upgrade is in progress. `Deps.UpdateBase` seam lets tests point the check at an `httptest` server.

### 5. Helper action `update-start` (new, the only privileged addition)
Request: `{expect, initiator}`. **No URL, path or arch from the caller.**
1. Refuse if `buildinfo.Version == "dev"`, if a PHP job unit is active, or if the upgrade lock is held.
2. Fetch `ManifestURL`, verify, require `manifest.version == expect`, `Newer(running, expect)`, `running >= min_upgrade_from`, and the host arch present in `debs`.
3. Write `/var/lib/servanago-update/job.json` (verified manifest bytes, signature, initiator, running version) and run
   `systemd-run --unit=servanago-upgrade --collect --property=Type=oneshot servanago update-job` through `Seam.Exec` (new `Seam` method `StartTransient(unit string, argv ...string) error`; add to the interface, `RealSeam`, `fakeSeam`). Returns immediately.
Why a transient unit: it lives outside `servanago-helper.service`'s cgroup, so `prerm` stopping the helper does not kill the upgrade.

### 6. `servanago update-job` (root, the orchestrator)
State machine written to `state.json` after each step (`phase`, `message`, `started`, `from`, `to`); a second `flock` on `/var/lib/servanago-update/lock` prevents overlap.

| # | Phase | Action | On failure |
|---|---|---|---|
| 1 | `verify` | re-verify manifest from `job.json` | abort, nothing changed |
| 2 | `stage-previous` | fetch `ManifestAt(running)`, verify, download that `.deb` to `prev/`, check sha256 | **abort**: no rollback possible means no upgrade |
| 3 | `download` | download the new `.deb` (https, 300 MiB cap) to `new/`, check sha256 and size; `dpkg-deb -f` must report `Package: servanago` and `Version:` equal to the manifest | abort |
| 4 | `backup` | `systemctl stop servanago servanago-helper`; copy `servanago.db`, `-wal`, `-shm` to `servanago.db.pre-<running>` (0600, servanago-owned like the other `.pre-*` copies) | start units again, abort |
| 5 | `install` | `dpkg --force-confold -i new/servanago_X.deb` | go to rollback |
| 6 | `start` | `daemon-reload`, start helper then app (postinst will not: units were stopped before `prerm`) | rollback |
| 7 | `health` | poll `http://<UI_LISTEN from the env file, default 127.0.0.1:8080>/login` for 200, up to 60 s, and require both units active | rollback |
| 8 | `done` | write `result.json` `{ok:true,from,to,initiator,at}` | n/a |
| R | `rollback` | stop units, `dpkg --force-confold --force-downgrade -i prev/...`, restore the three DB files, start helper then app, health-check; write `result.json` `{ok:false,rolledback:true,error}` | if the rollback health fails too: `result.json` `{needs_hands:true}` with the manual commands; units left stopped |

The orchestrator never opens sqlite and never runs the new binary before dpkg has installed it. It does run from the old binary's already-open inode, which dpkg's rename-into-place does not disturb.

### 7. Audit and result handling (web)
At start, `Server` reads `result.json` once if present and writes `update.completed`, `update.rolledback` or `update.needs_hands` (actor = the stored initiator, else `system`) and renames the file to `result.json.seen`. The Updates page shows the last result. The audit row is written after the restart, so the log shows the real outcome, not an intention.

### 8. Surfaces
- **CLI** `servanago update [--check] [--yes]`: `--check` fetches and prints; otherwise it asks for confirmation, calls `update-start` through the helper client (root/sudo only) and tails `state.json` until done.
- **MCP**: `check_update` (read: running, latest, last result, busy reason) and `upgrade` (write: `version` required, `ack_breaking`, `password` as for other re-auth tools; `mcpRun` the UI handler). Extend `toolLike` verbs with `check|upgrade` (the regex in `TestAgentSkillsMatchTheMCPTools`), add both to `skills/servanago-sites` or `servanago-setup` with "since X.Y.Z", `docs/mcp.md`, `llms.txt`.
- **Docs**: `docs/configuration.md` (`SERVANAGO_UPDATE_CHECK`), `docs/security.md` (what is verified and the one new root action), `docs/install.md` ("Updating"), RELEASING.md.

### 9. Release process (`docs/RELEASING.md`, `scripts/release-manifest.sh` + a hidden `servanago manifest build|sign` subcommand)
After `make deb`: `servanago manifest build --deb bin/servanago_X_amd64.deb --notes URL [--breaking]` computes sha256/size, sets `schema_change` when `git diff --name-only vPREV..HEAD -- internal/store/migrations` is non-empty, and writes `latest.json`; `servanago manifest sign --key $KEYFILE latest.json` writes `latest.json.sig`. `gh release create` attaches the `.deb`, `latest.json` and `latest.json.sig`. A test checks that `control`, `build-deb.sh` and the ldflags agree (extends the existing version-places checks).
The signing key (Ed25519 seed) lives offline outside the repo; its custody is open question 2 in the requirements.

## Failure modes and answers

| Risk | Answer |
|---|---|
| Hijacked GitHub account / release | The attacker still lacks the Ed25519 key: manifest and sig fail verification. |
| Valid manifest pointing at an attacker URL | URL pattern rule in `update.Verify`; the helper rebuilds the expected URL itself. |
| Replay of an old signed manifest (downgrade) | `Newer(running, X)` in both the helper and the job; the page only offers the latest. Residual: an attacker who blocks traffic can serve an old (still valid) manifest and hide a newer release. Acceptable; no mitigation planned. |
| Upgrade kills its own process | Transient unit with its own cgroup. |
| New version fails to migrate | Health check fails, rollback restores the DB copy and the staged previous `.deb`. |
| Network down mid-rollback | The previous `.deb` is staged **before** anything changes. |
| PHP build running | Web preflight and a helper-side re-check of the build units. |
| Site units during the restart | Unchanged from today's manual upgrade: units are not touched. |
| Power loss during dpkg | dpkg's own recovery (`dpkg --configure -a`); `state.json` would say `install`; the Updates page shows "interrupted" with the manual commands. |

## Tests

- `update`: signature good/bad/tampered/wrong key/rotated key; URL rule; semver incl. `dev`; manifest parsing fuzz.
- helper: `update-start` against a fake seam: tampered manifest, wrong `expect`, downgrade, `dev`, busy build, no arch. Fuzz that the request cannot carry a URL or path.
- job: orchestrator with fakes for dpkg, systemctl, HTTP, clock: success; failure at each of steps 2 to 7 each ending in the right state; rollback success; rollback failure → `needs_hands`.
- web: check on/off/env override, mail once per version, upgrade refused when busy / bad password / no `ack` for breaking, page renders complete (`>Save</button>`-style completeness assertion), result file → audit row.
- MCP tools + skill-coverage test. Migration idempotence.
- e2e: Updates page with the check pointed at a mock manifest; no real upgrade in e2e.
- Manual, before shipping: a rollback rehearsal on a scratch VM or bee with a deliberately broken release deb (migration that errors).

## Stages (each ends at `make check`)

1. `buildinfo` + `update` package (verify, URL rule, semver) + `manifest` subcommands + release script + RELEASING.md. Verify: unit tests.
2. Migration 009 + check loop + notify + Updates page (read-only) + MCP `check_update` + docs.
3. Helper `update-start` + `Seam.StartTransient` + fakes + fuzz.
4. `update-job` orchestrator with fakes, then the rehearsal on a scratch host.
5. Upgrade button, preflight, result→audit, CLI `update`, MCP `upgrade`, skills/docs, e2e.
6. Release that introduces the updater (hand-installed); the next release is the first self-upgrade.

## Resolved from the requirements' open questions

1. Signing tool: Ed25519 via the Go standard library, own tiny `manifest sign`.
3. Restart: dpkg's `prerm`/`postinst` stay as they are; the job stops units before dpkg and starts them itself.
4. Source/dev builds: notice only.
5. `breaking`: manual flag; `schema_change` derived from new migrations.
6. Air-gapped: **deferred** (`update --from FILE` is not in the first version).
7. First self-upgrade is the release after the one that ships the updater; the job also needs the running version's manifest, so versions from the updater release on only.

## Settled 2026-11-01 (user)

- **Key custody:** a passphrase-protected Ed25519 key file on the release machine, outside the repo (for example `~/.config/servanago/release.key`), with an offline backup. `manifest sign` reads the path from `--key`. Not in CI, no hardware token in v1. A leaked key lets an attacker push root-installed updates: document revocation (ship a release signed by the old key that drops it from the compiled-in list) in docs/security.md.
- **State dir:** `/var/lib/servanago-update`, root-owned 0755. The web user reads, never writes.
- **Rollback failure:** units stay stopped and `result.json` carries `needs_hands` plus the manual commands. Because the panel is down, the commands also go to the journal and to `/var/lib/servanago-update/NEEDS_HANDS.txt`.

No open questions remain; ready for `/sc:workflow` or `/sc:implement` (stage 1).
