# Built-in updater: requirements

Status: requirements settled 2026-11-01 (brainstorm). Design not started. Next step: `/sc:design`.

## Goal

An administrator can see that a newer ServanaGo exists and upgrade to it from the panel, the CLI or MCP, with the upgrade verified, audited and reversible. Today an upgrade is `scp` + `dpkg` by hand (docs/RELEASING.md, skills/servanago-setup).

## Decisions (user, 2026-11-01)

| Topic | Decision |
|---|---|
| Scope | One-click upgrade (check, notify, install). No unattended install. |
| Trust | Signed `latest.json`; the public key is compiled into the binary; the helper installs only when signature AND sha256 both match. |
| Location | Release assets only (`/releases/latest/download/latest.json` and `latest.json.sig`), not committed to the repo. Differs from the original "in the repo" wording: no commit, no CDN lag, file always matches its .deb. |
| Rollback | Automatic: keep the old .deb and a DB copy, health-check `/login` for about 60 s, reinstall the old .deb and restore the DB on failure. |
| Preflight | Refuse during a PHP build, backup or scan job; password re-auth; extra confirmation for a breaking or schema-changing release; refuse a downgrade or same version. |
| Check | On by default, weekly, opt-out (`SERVANAGO_UPDATE_CHECK=false` and a Settings toggle); no identifiers sent; Check now button. |
| Surfaces | Updates card/page, mail + ntfy notice (reuse the PHP-check notifier), MCP tools, `servanago update` CLI. Stable channel only. |

## Functional requirements

1. **Release process** writes `latest.json` (version, deb URL, sha256, released date, notes URL, `breaking` flag, `min_upgrade_from`), signs it, and attaches both files plus the .deb to the GitHub release. Add to docs/RELEASING.md; a test must fail if the version places and the manifest disagree.
2. **Check**: scheduled weekly job and a manual button; stores the last result (settings row, like `php_check_json`); compares semver with the running version; surfaces "update available" on the dashboard.
3. **Notify**: one mail/ntfy message per new version (dedupe like `Notified` in the PHP check).
4. **Upgrade** (helper action, closed and typed): download the .deb from the URL in the verified manifest only; verify signature, sha256 and that the .deb's `Version:` equals the manifest; copy DB to `servanago.db.pre-<ver>`; keep the old .deb; `dpkg --force-confold -i`; `daemon-reload`; start helper then app; health-check; roll back on failure.
5. **Audit**: `update.checked` (system), `update.upgrade`, `update.rolledback` with the acting user.
6. **Surfaces**: UI page with notes link and progress; MCP `check_update` (read) and `upgrade` (write); CLI `servanago update [--check]`.
7. **Docs**: configuration.md (env var), security.md, mcp.md, llms.txt, SKILL.md for each new MCP tool ("since X.Y.Z").

## Non-functional requirements

- The helper never takes a URL, path or version from the web process; it re-fetches and re-verifies the manifest itself. Fuzz the action like the other helper actions.
- Download over HTTPS only, size-capped, to a root-owned temp dir; the web user cannot influence the file.
- The signing private key never lives in the repo or on a host; document where the release machine keeps it and how a key rotation ships (new key must be signed by the old one, or a manual reinstall).
- No outbound call when the check is disabled; works behind the env proxy.
- Tests use a fake manifest server and fake seam; no real GitHub or dpkg. A live rollback rehearsal on a scratch host is part of done.

## Acceptance criteria

- A host on version N sees "N+1 available" within a week or after Check now.
- A tampered manifest, a wrong sha256, a mismatched `.deb` version and a downgrade are each rejected with a specific message and no change on disk.
- A deliberately broken release (migration error) is rolled back, the old version serves `/login` again, and the audit log shows both events.
- During a PHP build the Upgrade button is disabled with the reason.

## Open questions

1. Signing tool: minisign vs `ssh-keygen -Y sign` (the latter needs no new dependency; the Go verifier is small either way).
2. Key custody and rotation: who holds the private key, hardware token or file, and the rotation story.
3. Does the helper restart `servanago` itself, or does the package postinst do it? The helper is itself replaced mid-upgrade: run the install from a transient systemd unit (`systemd-run`) so the upgrade survives its own restart.
4. Hosts installed from source (not dpkg): updater shows the notice only.
5. `breaking` semantics: derived from "new migration in this release" or set by hand in the release script?
6. Air-gapped hosts: offer `servanago update --from FILE` with the same verification?
7. v1 and bee are the first real runs; the first updater release can only be installed by hand, so the earliest self-upgrade is the release after it.
