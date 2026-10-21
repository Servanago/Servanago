# PHP from source: requirements

Status: requirements only (output of brainstorm). Architecture and helper action design come next (`/sc:design`).

## Goal

Patch PHP in minutes without depending on apt mirrors, which are overloaded during an incident (trigger: CISA alert of 2026-10-21, critical PHP vulnerabilities requiring immediate patching). PHP management is driven entirely from the web UI.

The CVE IDs and fixed versions in that alert (CVE-2026-109618 and CVE-2026-109619, fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35) were read through a summarising fetch tool and are not verified against php.net.

## Current state (from the code)

- `runtimes.Detect` globs `php-fpm*` in `/usr/sbin`, `/usr/bin` and `/usr/local/bin` only, and parses the version from the binary name (`php-fpm8.2` gives `8.2`). A source build under `/usr/local/sbin` or `/opt` is not found.
- `helper.UnitInstall` runs `FPMTest` on the pool but never calls `CheckBinary` for php-fpm; that check applies only to frankenphp and cgi. The php-fpm master runs as root, so a source-built binary must be checked the same way.
- The Caddy route (`caddycfg.phpRoute`) and the unit and pool templates do not care where the binary lives. Only detection, the pick list and the binary path in the helper spec change.
- Decision to revisit: "runtimes are detected, never installed by Servanago". Building PHP replaces it for PHP only.

## Scope

- Compile the php.net tarball, NTS flavor: php-fpm and php-cli.
- Servanago downloads and builds the libraries it needs (openssl, curl, libxml2, ICU, zlib, libzip, image libraries, libpq, oniguruma, sqlite) into its own prefix. It never calls apt. The host needs only a compiler toolchain (gcc, make, pkg-config), checked up front with the missing items listed.
- Each PHP version is built once with every selectable extension as a shared `.so`. Each site selects its own extension set, loaded through a per-site ini. Groups: core (mbstring, opcache, pdo_sqlite, sqlite3, ctype, filter, tokenizer, session, fileinfo, phar), web-app (xml, curl, openssl, zip, gd, intl), databases (mysqli, pdo_mysql, pgsql).
- Only active and security-fix branches can be built (from php.net supported-versions data). EOL branches are refused; existing EOL builds show an "unsupported" badge.
- A small fixed set of PECL extensions (redis, apcu, imagick), each built as a shared `.so` against the same build and selectable per site. The admin said this must be "configurable from the web UI"; what is configurable (the per-site selection only, or the list of available PECL extensions itself) is open, see the open items.
- Composer is managed by Servanago.
- FrankenPHP from source (ZTS flavor, Go toolchain) is in scope but is a separate later milestone.

## Functional requirements

### Builds
1. A PHP page lists available releases, built releases, the sites on each build, and pending library updates.
2. Build and Switch actions show live logs and progress.
3. Builds live in versioned prefixes `/opt/servanago/php/<ver>-<n>/`, owned by root.
4. Each build keeps its log under `/var/log/servanago/php-build-<ver>-<n>.log`, linked from the PHP page. There is no stored build manifest.
5. The previous build per branch is kept. Other builds are pruned on request. A build pinned by any site or user default cannot be pruned.
6. Builds run one at a time.

### Updates
7. A weekly cron job and a "Check now" button read the php.net release feed and the bundled libraries' release feeds.
8. A new release raises a UI banner and an email through the existing SMTP settings. Nothing changes host state without an admin click.
9. "Update available" is marked security only when the php.net feed says so.
10. A library update marks the PHP builds that use it as needing a rebuild.

### Per-site pin and extensions
11. A site pins a branch by default (for example `8.4`), following the newest installed build on that branch. Pinning an exact build is an Advanced option.
12. The site form has an extension checklist. The chosen set is written to the site's pool as ini.
13. Switch rewrites the pool, runs `php-fpm -t`, restarts, health-checks, and reverts to the previous build automatically on failure.
14. One action can move every site on a branch to a new build.

### Per-user default CLI
15. Any non-system login user (UID >= 1000 with a real login shell) can have a default CLI PHP, set in the UI as a branch or an exact build. It is independent of site pins.
16. Delivery is a root-owned `/etc/profile.d/servanago-php.sh` (login and interactive shells) plus root-owned `php` and `composer` shims in `/usr/local/bin` (cron, `ssh host cmd`, IDE terminals). The mapping lives in `/etc/servanago/php-users/<user>`.
17. Nothing is written into a user's home or a site folder. The distro `php` is shadowed for these users and never removed; the UI shows it as "distro, not managed".
18. A user's `composer` runs under the same resolved `php`.
19. A user default pointing at a build that is switched, rolled back or pruned follows the switch; a pinned default blocks pruning.
20. Resolution order in the shim: user default, then the distro `php`.

### Composer
21. Servanago downloads `composer.phar` and verifies it with the checksum from getcomposer.org. Site install and build commands run with the site's pinned PHP first on `PATH`.

### Helper and audit
22. New helper actions (build start, status and cancel; install; prune; switch; set or clear user default; write profile.d, shims and mapping) are typed, validate every input, and are fuzzed like the existing ones. No free-form strings.
23. Audit events for check, build, switch, prune, `php.default.set` and `php.default.cleared`, with actor `system` for the cron check.

## Non-functional requirements

### Security
- PHP source is verified with its GPG signature and checksum. Library tarballs and composer are verified by checksum from the release feed, failing closed on any mismatch. The checksum from the same HTTPS feed protects against corruption, not a compromised feed.
- The build runs as a dedicated unprivileged `sg-build` user in a sandboxed transient systemd unit with a writable work directory only, resource caps, and no network after the download step. Only the final install step runs as root, copying a verified tree into a root-owned prefix. The helper never executes source as root.
- Source-built binaries must pass `CheckBinary` (root-owned, not group or world writable). This closes the current gap for php-fpm.
- The user picker excludes root and system users.

### Reliability
- A failed build or install leaves no half-installed prefix.
- Builds are capped on CPU, memory and disk: `make -j` is half the cores, `CPUQuota` is 50% of the cores, `MemoryMax=4G`, and a build refuses to start with less than 10 GB free on the work filesystem. Fixed defaults, not UI settings.
- A failed switch reverts automatically.

### Restore
- SQLite is the desired state: site pins, user defaults and site extension selections. At startup the reconciler regenerates the profile.d script, shims, pool files and user mappings from it.
- Builds are discovered from the filesystem (directory name, `php -v`, `CheckBinary`). There is no build manifest, because rebuilding a historical manifest would need old tarballs that upstream no longer hosts.
- A pin or default that points at a missing build falls back to the newest installed build on the same branch, or is flagged with a banner. It never crash-loops.
- A restore on a fresh host gets current PHP through "Build latest `<branch>`", not a recreation of old versions.

### Compatibility
- Apt PHP coexists. Detection finds `/opt/servanago/php/*` and the distro binaries.
- The shim is tiny POSIX `sh` and tested.

## Risks

- The shim runs for every user and cron job. A bug is a system-wide outage. Confidence: high.
- Servanago takes on CVE tracking for about 12 bundled libraries; openssl, curl and libxml2 are the heavy ones. A weekly check is slower than an incident. Confidence: high.
- A full build from scratch takes tens of minutes, so "patch in minutes" does not hold for a library rebuild. Confidence: moderate.
- There is no library vulnerability feed. The UI cannot tell a security library release from a feature release. Confidence: moderate.
- `sudo php` bypasses profile.d because of `secure_path`. Absolute paths and shebangs bypass the default. Accepted.
- With no manifest, which libraries went into a build is known only from its build log. A restore may move a branch-pinned site to a newer patch release.
- FrankenPHP needs a ZTS PHP build, a Go toolchain and the Caddy modules. It roughly doubles build work, and every PHP security release then needs two compiles.

## Milestones

1. Detect `/opt/servanago/php/*`, the `sg-build` user, and the lib and PHP builder (NTS: fpm and cli), built from the UI.
2. Per-site pin, extension checklist, switch with health check and auto-revert.
3. Per-user default CLI (profile.d and shims).
4. Weekly check, "Check now", banner and email.
5. Composer management.
6. FrankenPHP from source.

## Open items for design

- PECL "configurable from the web UI": either (a) the fixed set redis, apcu, imagick with per-site selection in the UI, or (b) the admin can add or remove entries in the available PECL list from the UI. (b) means admin-supplied names and versions fetched from the network and compiled by the build user, which needs strict name and version validation and a verification source (PECL publishes checksums on pecl.php.net; not yet checked). Needs the admin's answer before milestone 2.
- Verify the CISA CVE IDs against php.net. (The fixed versions 8.5.12, 8.4.27, 8.3.36 and 8.2.35 match php.net's release JSON, which also carries a `security` tag; the CVE IDs are still unchecked.)
- Whether a short-lived download cache is kept for retrying a failed build (a design detail).
- Where the extension ini and per-build `php.ini` live, and how the pool references them.
- How the health check after a switch decides success.
