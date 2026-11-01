# Releasing

Work on a branch, fast-forward `main` only after `make check` passes, push, tag, release, then deploy when asked.

## Version

The release version appears in these places; change all of them:

1. `packaging/DEBIAN/control` (`Version:`)
2. `packaging/build-deb.sh` (default output name)
3. `packaging/install.sh` (the `.deb` glob)
4. `README.md` (the two `make deb` / `apt-get install` lines, also in `docs/install.md`)
5. `cmd/servanago/packaging_test.go` (expected `Version:`)
6. `.claude-plugin/plugin.json` (`version`)

Also update the version mentioned in `llms.txt` (the status line and the install line).
`TestAgentSkillsMatchTheMCPTools` fails if `plugin.json` and `control` disagree.

## Agent skills

`skills/` holds the agent skills installed with `npx skills add Servanago/Servanago` (or as a Claude Code plugin).

- A new, renamed or removed MCP tool must be reflected in the matching `skills/*/SKILL.md`. The test above fails if a registered tool is in no skill or a skill names a tool that does not exist.
- Each skill has the line `Requires ServanaGo X.Y.Z or newer.`: the release that introduced the tools or behavior it describes. Raise it when a skill starts describing something newer; it may never exceed the release being cut.
- Skills are generic and public: no hostnames, ssh aliases or personal paths.

## Steps

1. Branch, change, `make check` (run one at a time; judge it by the `exit=` line of its log).
2. Bump the version everywhere above. Schema changes are a new `NNN_*.sql` migration, never an edit of an existing one; bump the hard-coded `user_version` in `TestMigrationsIdempotent`.
3. `make deb`; commit; fast-forward `main`; push.
4. `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`
5. `packaging/release-manifest.sh bin/servanago_X.Y.Z_amd64.deb ~/.config/servanago/release.key [--breaking]` writes and signs `bin/latest.json` (it sets `schema_change` itself when the release adds a migration; pass `--breaking` when the admin must act on the release).
6. `gh release create vX.Y.Z bin/servanago_X.Y.Z_amd64.deb bin/latest.json bin/latest.json.sig --title vX.Y.Z --notes ...`. Say in the notes anything that changes behavior on upgrade (for example a new opt-in environment variable).

## Signing key

`bin/servanago manifest keygen FILE` creates the Ed25519 key (mode 0600, outside the repo; keep an offline copy) and prints the public half, which goes into `update.Keys` (`internal/update`). Releases are signed only by that key. A rotation ships a release that lists the old and the new public key. A leaked key is revoked the same way: a release signed with the old key that no longer lists it. Until the first key is added to `update.Keys`, no build trusts any manifest.

## Deploy

Only when asked. Follow the upgrade steps in `skills/servanago-setup/SKILL.md`: compare sha256, stop the units, back up the database, `dpkg --force-confold -i`, start the helper then the app, verify `/login` and the journal. Options added to `servanago.env` in a release do not reach an existing host (`--force-confold`); add them by hand.
