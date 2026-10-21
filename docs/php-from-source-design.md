# PHP from source: design

Input: `docs/php-from-source-requirements.md`. Rule applied throughout: reuse what exists, add the least that meets a requirement, say where a shortcut has a ceiling.

Things checked against the code and php.net while designing are marked **(verified)**. Things I did not read are listed in section 12 and must be checked before implementation.

## 1. Shape of the solution

- A PHP "build" is a directory, `/opt/servanago/php/<ver>-<n>/` (for example `8.4.27-1`). The filesystem is the only record of what is installed. No build table.
- A site's pin is the existing `sites.fpm_version` column, now holding a **label**: a branch (`8.4`, follows the newest build on that branch), an exact build (`8.4.27-1`), or a legacy apt label (`8.2`, unchanged).
- Detection (`runtimes.Detect`) turns build directories into the same `PHPVersion{Version, Path}` entries it already returns. The pick list, `runtimeApply` and the helper binary check then work with almost no change.
- The build is a transient systemd unit running an embedded shell script as an unprivileged user. Status and logs reuse the existing `unit-status` and `unit-logs` helper actions. One build at a time comes free from the unit name being unique.
- Per-site extensions are a per-site `php.ini` written from a template, passed with `-c` on the site's own php-fpm master.
- The per-user default CLI is a tiny root-owned shim plus a profile.d snippet, driven by one file per user.

## 2. Disk layout

```
/opt/servanago/php/                      root:root 0755, created by the helper
  8.4.27-1/                              one build; self-contained except the libs below
    sbin/php-fpm  bin/php  bin/phpize    php.ini-less; extensions are shared .so
    lib/php/extensions/no-debug-non-zts-*/
    libs.txt                             one line per lib dir used, e.g. openssl-3.5.4
  libs/<name>-<ver>/                     shared, immutable; built once, reused by later PHP builds
/opt/servanago/composer/composer.phar    root:root 0644
/etc/servanago/php/<slug>.ini            per-site ini (extensions)   [helper writes]
/etc/servanago/php-users/<user>          one line: a label           [helper writes]
/usr/local/bin/php, /usr/local/bin/composer, /etc/profile.d/servanago-php.sh   [helper writes]
/var/lib/servanago-build/current/       work dir for a running build, owned by sg-phpbuild (see section 16)
/var/log/servanago/php-build-<ver>-<n>.log
```

Libraries live in shared immutable directories instead of one copy per build. A PHP-only security release (exactly the CISA case) then compiles only PHP, and libraries are rebuilt only when a library version changes. PHP is linked with a `RUNPATH` to `libs/*/lib`, so no `ld.so` configuration is touched.

Ceiling: a library directory is never modified, so a library security update means a new `libs/<name>-<newver>` and a PHP rebuild linked to it.

## 3. Data model (one schema edit, in `001_init.sql`)

| Change | Why |
|---|---|
| `sites.php_extensions TEXT NOT NULL DEFAULT ''` | Space-separated names from a fixed allowlist. Empty means the core set. |
| `sites.php_health_path TEXT NOT NULL DEFAULT ''` | Optional path requested after a switch (section 7). |
| table `php_user_defaults(username TEXT PRIMARY KEY, version TEXT NOT NULL)` | Per-user default CLI label. |
| `settings.php_check_json TEXT NOT NULL DEFAULT ''`, `settings.php_checked_at INTEGER NOT NULL DEFAULT 0` | Last update-check result (what to show in the banner). |

This changes the schema, so the live `data/servanago.db` needs one more conversion (CLAUDE.md procedure). Tell the user at that point.

There is no `php_builds` table, no job table and no manifest. Pins and defaults store labels, never paths.

## 4. Label resolution (pure function in `internal/runtimes`)

`Resolve(label string, installed []PHPVersion) (PHPVersion, bool)`:

1. Exact build label (`8.4.27-1`): that build if present.
2. Branch label (`8.4`): the newest source build whose version starts `8.4.`; else the apt entry whose label is `8.4`.
3. Exact build missing: fall back to the newest source build on the same branch and report that it was a fallback (the UI shows a banner). No match at all returns false and `runtimeApply` fails with a notice, as it does today for a missing apt version.

Detect changes:
- Add `/opt/servanago/php/*-*/sbin/php-fpm` to the globbed paths. Source builds are listed before apt entries so `dedupe` keeps the source build when both offer `8.4`.
- Report each source build twice: once with its exact label, once as the branch label pointing at the newest build on that branch.
- `PHPVersion` gains `Source bool` and `Libs []string` (read from `libs.txt`). No other field.
- Sort stays `newest()`, which already compares numeric parts.

## 5. Helper actions

Existing machinery reused: `Request`/`Spec`, typed actions, the `Seam` interface, `put()` (write, verify, roll back), `unit-status`, `unit-logs`, `UserAdd`, `CheckBinary`.

| Action | Does | Notes |
|---|---|---|
| `php-build` | Starts the build unit for one PHP version. Returns at once. | Spec: `PHPVersion` matching `^[0-9]+\.[0-9]+\.[0-9]+$`. |
| `php-install` | Root install of a finished build into `/opt/servanago/php/<ver>-<n>`. | Section 6. |
| `php-prune` | Removes one build directory, then library directories no remaining `libs.txt` names. | Refuses nothing about pins: the web layer checks pins first. The helper refuses a path outside `/opt/servanago/php/`. |
| `php-user-default` | Writes or removes `/etc/servanago/php-users/<user>`, and (re)writes the shims and profile.d. | Section 8. |
| `composer-install` | Verified `composer.phar` into `/opt/servanago/composer/`. | Milestone 5. |

Changes to existing helper code:
- `fpmBinRE` also accepts `^/opt/servanago/php/[0-9]+\.[0-9]+\.[0-9]+-[0-9]+/sbin/php-fpm$`. The "version label equals the binary name" check becomes "label is the branch or exact build of this binary".
- `UnitInstall` calls `CheckBinary` for php too (**closes the gap found in research**). Distro `php-fpm` is root-owned and not group/world writable, so it passes.
- `poolTemplate` is unchanged. `phpUnitTemplate` ExecStart gains `-c /etc/servanago/php/<slug>.ini`. `FPMTest(bin, conf)` gains the ini path, because `php-fpm -t` must load the same extensions. `UnitInstall` writes the site ini (from `Spec.Extensions`, validated against the allowlist, template text only) before the pool.
- `Spec` gains `Extensions []string`, `PHPVersion string`, `User string`, `Build string` (an exact build label, validated). No free-form strings.
- Reserve the slug `phpbuild` (used by the build unit and its user), and the web slug validator rejects it.

Fuzz targets (same style as `FuzzUnitInstallNoInjection`): the extension list against ini injection, `User`, `Build`, `PHPVersion`, and the install copy (section 6).

## 6. Build pipeline

One embedded script, `internal/helper/phpbuild.sh` (POSIX sh, `//go:embed`), two phases:

1. **fetch** (network on): downloads the PHP tarball, its `.asc` and each library tarball into the work directory. PHP is checked with `gpg --no-default-keyring --keyring <embedded php-keyring.gpg> --verify` **and** the `sha256` from `https://www.php.net/releases/index.php?json&version=<branch>` (**verified**: the response has `source[].filename` and `source[].sha256`, and the keyring is `https://www.php.net/distributions/php-keyring.gpg`, 51 KB). Library versions and checksums are resolved from each library's release feed (section 11). Any mismatch or unresolved library aborts.
2. **build** (`PrivateNetwork=yes`): libraries not already present (`libs/<name>-<ver>`), then PHP with `--prefix=/opt/servanago/php/<ver>-<n> --enable-fpm --enable-<ext>=shared ...` and `make install DESTDIR=<work>/stage`.

Both run through `systemd-run --wait --collect --unit=servanago-phpbuild` as `sg-phpbuild` with `ProtectSystem=strict`, `ReadWritePaths=<work dir>`, `NoNewPrivileges`, `PrivateTmp`, `MemoryMax=4G`, `CPUQuota=<50% of cores>` and a long `TimeoutStartSec`. `make -j` is half the cores. Before starting, the helper requires 10 GB free on the work filesystem. These are fixed values (decided), not UI settings. The helper never runs source as root.

Sequence driven by the web layer (a goroutine started by the build button; the state needed to resume is in the work directory):

```
POST /php/builds  ->  php-build (start unit)  ->  poll unit-status / unit-logs every 3s (htmx)
unit succeeded    ->  php-install             ->  build appears in detection
```

If the web process restarts mid-build the work directory still holds `stage/`; the page lists "Finished build awaiting install: Install / Discard". That keeps the design stateless without a jobs table.

**php-install (root, the only step that touches root-owned paths).** The unit has exited, so nothing is writing to `stage/`. The helper walks `stage/` itself in Go (it does not shell out to `cp`):
- copies regular files and directories only; refuses device nodes, hard links and any symlink that is absolute or whose target leaves the stage tree;
- clears setuid, setgid and group/other write bits, chowns to `root:root`;
- writes into `/opt/servanago/php/.tmp-<ver>-<n>` then renames to `<ver>-<n>`, so a failure leaves no half-installed build;
- then verifies: `CheckBinary` on `sbin/php-fpm` and `bin/php`, `bin/php -v` reports the requested version, `bin/php -m` lists every shared extension that was built, and `php-fpm -t` accepts a minimal pool. Any failure removes the new directory.
- `<n>` is the next free number for that version.

The log is copied to `/var/log/servanago/php-build-<ver>-<n>.log` after the install.

Preflight (Go, before starting the unit): `gcc g++ make pkg-config perl cmake curl gpg xz` are present. The response lists the missing ones with the matching `apt install` line. Servanago never runs apt.

EOL refusal lives in the web layer: the build form only offers versions whose branch is in `supported_versions` (**verified**: present in the php.net release JSON; `active.php` carries no support or EOL data). The helper's authenticity guarantee is the GPG check, not the web list.

## 7. Switch and rollback (no new helper action)

A switch is: re-apply each affected site through the existing path, with the site's binary resolved from its label.

```
for each site whose label resolves to a different binary than its running unit:
    old := current spec (binary, label)
    UnitInstall(new spec)          // put(): pool/ini/unit written, php-fpm -t and systemd-analyze verify first
    UnitStop, UnitStart
    wait 3s, UnitStatus: ActiveState == "active" and SubState == "running"
    if the site has a health path: GET it through Caddy (Host header = primary hostname), require status < 400
    on failure: UnitInstall(old spec); UnitStart; audit php.switch.reverted; flash the reason
```

"Switch all sites on this branch" is the same loop over the sites whose label is that branch. Switch one site at a time and stop the loop at the first revert, so a bad build never takes every site down.

**Health path (decided: optional per-site URL).** New column `sites.php_health_path TEXT NOT NULL DEFAULT ''`, a path such as `/healthz`, validated as an absolute URL path (no scheme or host, no whitespace or control characters, at most 200 characters). The request goes to the local Caddy listener on 127.0.0.1 with the site's primary hostname as `Host`, with a 10-second timeout and no redirects followed beyond one.
- The request passes through the site's gate, allowlist and basic-auth chain. A gated site therefore needs the path to be reachable without login, or it gets a 401/302 and the check reads it as a pass only when the status is below 400. State this in the field's help text: a health path behind the gate must be an extra route or the gate must allow it, otherwise leave the field empty.
- Empty path means the unit-active check only (the default).

The previous build is kept because `php-prune` runs only on request and the web layer refuses to prune a build that any site pin, user default or "newest on its branch" mapping needs.

## 8. Per-user default CLI

Mapping file `/etc/servanago/php-users/<user>` holds one label. Because it stores a label and not a path, a branch default follows a new build automatically and needs no rewrite after a switch.

`/usr/local/bin/php` (written from an embedded template, about 15 lines of POSIX sh):

```
label = contents of /etc/servanago/php-users/$(id -un)       # no file -> exec the distro php
exact label  -> /opt/servanago/php/<label>/bin/php
branch label -> newest dir matching /opt/servanago/php/<branch>.*-*, chosen with sort -V
dir missing  -> exec the distro php (/usr/bin/php), never fail
```

`/usr/local/bin/composer` runs `php /opt/servanago/composer/composer.phar "$@"` through the same resolution. `/etc/profile.d/servanago-php.sh` prepends the resolved `bin/` to `PATH` for login shells, so `phpize` and friends come along.

`php-user-default` validates the user: `os/user.Lookup`, UID >= 1000, the shell in `/etc/passwd` is not `nologin` or `false`, name matches `^[a-z_][a-z0-9_-]{0,31}$`. Shims are written with `put()` semantics (temp file, rename, no symlink targets). Clearing the last user default leaves the shims in place (they fall through to the distro `php`); removing them is not needed.

The shim is the one file that runs for every user and cron job: it gets its own shell test (sh -n, plus run against a temp `/opt` tree through a `SERVANAGO_PHP_ROOT` override that exists for the test only).

## 9. Update check

A weekly timer inside the web process (a goroutine with a `time.Ticker`, plus a run at start when `php_checked_at` is older than 7 days) and the "Check now" button call the same function:

1. For each branch the admin has a build for, GET `https://www.php.net/releases/index.php?json&version=<branch>` (**verified** shape: `version`, `tags` containing `"security"` for a security release, `date`, `supported_versions`).
2. Newer than the newest installed build on that branch: record it, marked security when `tags` contains `security`. Store the JSON in `settings.php_check_json` and set `php_checked_at`.
3. The PHP page shows a banner. Mail through the existing SMTP sender (same one the magic-link gate uses) only when the set of available releases changed since the last check, so a week of unchanged results sends nothing.
4. Audit `php.check` with actor `system`.

The check also resolves each library's latest version (section 11) and compares it with the `libs.txt` of the newest build; "libraries behind" joins the banner. The check never builds or switches anything.

## 10. Web surface

New page `/php` (template `php`), handlers in a new `internal/web/php.go`:
- tables: installed builds (size, sites on it, libs from `libs.txt`, EOL badge), available releases, user defaults;
- actions: Build (re-auth), Install/Discard (awaiting-install), Switch branch (re-auth), Prune (re-auth), set/clear user default, Check now;
- live build panel: the same polling pattern as `unitPanelFor`, reading `unit-status`/`unit-logs` for `phpbuild`;
- site form: the pick list now comes from `phpVersionOpts(rep.PHP, ...)` unchanged, plus an extension checklist bound to `sites.php_extensions`, validated against the shared allowlist (`internal/runtimes`, same pattern as `FrankenPaths`).

Help text goes in `internal/web/help.go` (the test fails on undefined hints). All mutating handlers follow the existing rules: `fail()` for errors, 204 plus `HX-Redirect`, `HX-Request` for CSRF, `s.audit(...)`.

Audit actions: `php.build.start|ok|failed`, `php.install`, `php.switch`, `php.switch.reverted`, `php.prune`, `php.default.set|cleared`, `php.check`.

Startup reconcile: regenerate every site's ini, pool and unit (the existing runtime reconcile), then rewrite the shims, profile.d and mapping files from `php_user_defaults`. A label that resolves to nothing becomes a banner, never a failed start.

## 11. Libraries: live feed resolvers

About 13 libraries: zlib, openssl, curl, libxml2, libpng, libjpeg-turbo, freetype, libwebp, libzip, ICU, oniguruma, sqlite, libpq. ICU, openssl and libpq dominate build time.

**Decided: live feed resolvers for all libraries from milestone 1** (the user rejected pinning). Each upstream publishes releases differently (GitHub releases, FTP indexes, project pages), so this is about 13 small resolvers that will each break eventually.

- An embedded table lists, per library: `name`, the feed URL, the rule that extracts the latest version, the tarball URL template, and where the checksum comes from (sidecar file or release metadata). One Go function reads the table; a library with an odd format gets its own small extractor, not a framework.
- A resolver that fails or finds no checksum fails the build for that library with a clear message. A build never falls back to unverified source.
- Resolution happens in the **fetch** phase and the resolved version is written to `libs.txt`, so the PHP page and the update check can compare "built with" against "latest".
- Resolvers are tested against recorded feed fixtures (one per library), so a changed upstream page shows as a failing fixture refresh, not a surprise at 3am.
- Consequence to accept: the checksum now comes from the same feed as the file, so it detects corruption, not a compromised upstream. PHP keeps the stronger GPG check. If this worries you, pin a library's expected sha256 in the table for the ones that rarely change.
- The update check (section 9) uses the same resolvers, so a newer library release raises the "libraries behind" banner without new parsing code.

PHP's version, checksum and signature also come live from php.net, so a PHP-only incident needs no Servanago release.

**PECL (redis, apcu, imagick): decided in scope, UI meaning still open.** Each is built as a shared `.so` into the same build and listed in the per-site extension checklist like any other. The resolver table gains rows for them (pecl.php.net feed; ImageMagick as one more library, plus hiredis only if redis needs it). Whether the admin can also add or remove PECL entries from the UI is unresolved (requirements, open items). If yes, the table moves from the embedded file into SQLite with validated `name` (`^[a-z][a-z0-9_]{1,31}$`) and version, and the fetch phase gets a PECL checksum source; if no, it stays embedded and per-site selection is the only UI. Milestone 2 depends on the answer; milestone 1 does not.

## 12. Not read yet (check before implementing)

- How a site's install and build commands are executed today. The design needs the site's resolved `bin/` first on `PATH` for php sites; I did not read that code.
- The existing mailer and the reconciler entry points. I assumed both can be reused as described.
- Whether `unit-status` and `unit-logs` accept the reserved slug `phpbuild` without a site row. The helper only validates the slug pattern, from what I read, but the web layer may look the slug up.
- The composer.phar checksum URL format (milestone 5).

## 13. Tests

- Unit, pure: `Resolve`, `newest`/branch grouping, extension allowlist, `libs.txt` parsing, update-check comparison using recorded php.net JSON fixtures.
- Helper (fake `Seam`, extended with `FPMTest(bin, conf, ini)`): reject tables that assert why each row fails (`want` substring), build-path regex, user validation, prune path confinement. Mutate each guard once to see it go red.
- Install copy: temp-directory tests for symlink escape, absolute symlink, setuid bit, device node (skipped without root), hard link, existing target directory, plus a fuzz target.
- Signature check: a test keyring and a signed fixture tarball; assert a tampered file and a wrong key both fail.
- Shim: shell test against a temp tree.
- Web: `runtimeServer` pattern with `Deps.Exec` returning source-build globs; switch and revert paths with a fake helper that fails the second `UnitStart`.
- e2e: page renders, extension checklist saves, build button disabled with a missing-toolchain message. No real compile in CI (tens of minutes); a real build is a documented manual run on the local machine.

## 14. Milestone to files

| # | Scope | Mainly touches |
|---|---|---|
| 1 | Detect source builds, `sg-phpbuild`, `php-build`, `php-install`, library resolvers, `/php` page with live log | `runtimes`, `helper/phpbuild.go`, `phpbuild.sh`, `helper/phplibs.go` (resolver table), `web/php.go`, `templates/php.html`, `help.go` |
| 2 | Pin by label, extension ini, switch with revert, prune | `helper/runtime.go` (ini, `-c`, regex, `CheckBinary`), `store` schema, `siteform.go`, `web/runtime.go` |
| 3 | `php-user-default`, shims, profile.d, user picker | `helper/phpuser.go`, `web/php.go`, reconcile |
| 4 | Weekly check (in-process ticker), banner, mail, "libraries behind" | `web/phpcheck.go`, `settings` columns |
| 5 | Composer | `helper`, `web/php.go` |
| 6 | FrankenPHP (ZTS, Go toolchain) | separate design |

## 15. Risks that remain

- The shell build script is the least testable piece. It gets a manual run per milestone and `sh -n` in the gate.
- Library build recipes (ICU and libpq in particular) can break on a new upstream release, and with live resolvers a changed feed page breaks the build until Servanago ships a fix. Fixture tests catch format changes only after a fixture refresh; a failed build says which library and why.
- Builds run on the host CPU for tens of minutes; `CPUQuota` and `MemoryMax` keep the web app and sites responsive.
- `sudo php` bypasses profile.d (`secure_path`) and falls to the shim or distro `php`.

## 16. As built: where the code differs from sections 1 to 15

Written after implementation. Where this section and an earlier one disagree, this one is right.

- **The job is Go, not shell.** `servanago php-job fetch|build DIR` (`cmd/servanago/phpjob.go`, `internal/phpbuild`). There is no `phpbuild.sh`, no `systemd-run`, and no `internal/helper/phpbuild.go`. Two fixed unit files, `servanago-phpfetch.service` (network on, `OnSuccess=` the build unit) and `servanago-phpbuild.service` (`PrivateNetwork=yes`, `BindPaths=<job>/root:/opt/servanago/php`), are written by the helper from templates (`jobUnit` in `internal/helper/php.go`).
- **Job directory**: `/var/lib/servanago-build/current` (`phpbuild.Dir`), not `/var/lib/servanago/build`, because `/var/lib/servanago` is 0750 `servanago:servanago` and the job runs as `sg-phpbuild`.
- **Library reuse.** Libraries are installed once under `/opt/servanago/php/libs/<name>-<ver>` and reused. The fetch phase (which sees the real tree) copies the ones the build needs into the stage, and the build unit sees the stage at the final path, so every prefix and `RUNPATH` is the real one. `php-install` copies only libraries that are not installed yet.
- **Library versions** come from each library's release feed (`internal/phplibs`). Four exceptions: libpng, freetype and libwebp are **pinned** (version and sha256 in the table, `Resolved.Pinned`) because no feed publishes a sha256 for them (see the comments in `phplibs.go` for how each was checked), and sqlite is verified with **SHA3-256**, the only hash its download page publishes. A newer libpng, freetype or libwebp needs a Servanago release.
- **Host tools**: gcc, g++, make, pkg-config, perl, cmake, bison, flex, gpg, xz, tar (`phpTools`). bison and flex were added after a real build: PostgreSQL 18's configure (for libpq) stops without them even though the tarball ships the generated parsers.
- **Downloads retry** twice on network errors and 5xx answers (`phpbuild.HTTPGet`); a checksum mismatch is never retried.
- **Extensions.** ctype, filter, tokenizer, session, fileinfo, phar, pdo, openssl, libxml and zlib are always built in and not selectable. Selectable shared extensions: mbstring opcache sqlite3 pdo_sqlite dom simplexml xml xmlreader xmlwriter curl zip gd intl mysqli pdo_mysql pgsql pdo_pgsql (`runtimes.PHPExtensions`). **PHP 8.5 and later always include opcache** (checked in the 8.5.12 UPGRADING notes): no `opcache.so`, so it is neither loaded nor expected from an 8.5 build (`Ext.Shared`).
- **PECL: apcu and imagick** (added after the first cut), built into every PHP build as shared extensions. The source comes from Packagist's `php-ext` metadata (the format PIE, the PHP Foundation's PECL replacement, installs from) without running PIE: `phplibs.ResolveExt` takes the latest stable release and its commit, the job downloads GitHub's zipball of that commit, unpacks it with a path-checked Go unzip, and builds it with the new build's own `phpize`. **No checksum or signature exists for this source** (Packagist's dist `shasum` is empty, GitHub zipballs have no digest, PECL lists none). The decision was to trust Packagist and GitHub over HTTPS at that commit; the build log records each extension's commit and the zipball's sha256. A compromise of either would put malicious code into an extension that php-fpm loads as the site user. imagick needs ImageMagick, now a bundled library (`imagemagick`, from its GitHub release, sha256 digest). redis was dropped from the list. `unicode`/`unicodestring` (PECL, PHP 5-era, no PHP 8 releases) were not added; `intl` already covers ICU. A build made before apcu/imagick were offered has no `apcu.so`: `unit-install` refuses a site that selects an extension its build lacks (`checkBuildHas`), so the site is not started without it.
- **More host tools** for phpize: autoconf, automake, libtoolize, m4.
- **Status** is `php-status` (state file plus the journal of the two units), not `unit-status` with a reserved slug. The slugs `phpbuild` and `phpfetch` are still reserved (`store.reservedSlugs`).
- **Distro PHP is unchanged.** The per-site `php.ini` and `-c` apply only to ServanaGo's own builds. A distro build keeps its `php.ini` and `conf.d`.
- **`php-fpm` is now checked** with `CheckBinary` for every php site (the gap found in research is closed), distro builds included.
- **Routes** use `s.protected` and ask for the password through `s.confirm`, which does nothing in open mode (no administrator exists).
- **Startup.** `ReconcilePHP` writes every stored user default again. Site units are still not reconciled at startup: that gap existed before this work (`runtimeApply` runs only from handlers).
- **Install is automatic.** `watchBuild` installs a finished build and, if asked, switches the sites that follow the branch. A web restart during a build leaves the finished build waiting for the Install button.
- **The update mail** goes to the MAIL FROM address, because ServanaGo has no admin email field.
- **Not run against real systemd.** The unit files pass `systemd-analyze verify`-style checks only in tests with a fake; `BindPaths=` under `ProtectSystem=strict`, `OnSuccess=` and `PrivateNetwork=` have not been exercised on a real host. A real compile of PHP and every library was run with `go test -tags smoke ./internal/phpbuild` (see its header); that test uses one directory for the stage and the final tree, so it does not test the bind mount.
