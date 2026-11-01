# Requirements: build-time PHP extension selection

Status: requirements only (brainstorm 2026-11-01, feeds checked 2026-11-01). Design next (`/sc:design`).

## Goal
On `/php`, the admin ticks which extensions go into a PHP build. Each extension has a pre-set recipe in code. A site's own checklist then offers only what its build contains.

## Settled
- List is curated in code, not admin-typed (keeps the strict Packagist checks and the closed helper action set).
- A build-time checkbox decides what is compiled. Unticked = no `.so` in that build. `checkBuildHas` already enforces the site side.
- Libraries are built from source (`phplibs` recipes, feed checksums, under the build's `libs`).
- mcrypt dropped (removed from core in 7.2, unmaintained libmcrypt).
- Take PIE's `php-ext` metadata contract into Go (read it from the Packagist p2 feed); do not run PIE itself, and do not use its installer, solver, package-manager or ini steps. See "PIE logic to port".

## Packagist feed results (p2, latest stable, fetched 2026-11-01)

| Ext | Package | Latest | Type | `require.php` | dist repo | Notes |
|---|---|---|---|---|---|---|
| apcu | apcu/apcu | 5.1.28 | php-ext | >= 7.0 | krakjoe/apcu | `--enable-apcu` declared |
| imagick | imagick/imagick | 3.8.1 | php-ext | >= 5.6 | Imagick/imagick | `--with-imagick` (needs-value) |
| redis | phpredis/phpredis | 6.3.0 | php-ext | >= 7.4 | phpredis/phpredis | priority 60; igbinary/msgpack/lz4/lzf/zstd flags; extension-name `redis` |
| xdebug | xdebug/xdebug | 3.5.3 | **php-ext-zend** | **>=8.0,<8.6** | xdebug/xdebug | priority 90; no configure-options declared; refuses PHP 8.6 |
| memcached | php-memcached/php-memcached | 3.4.0 | php-ext | >= 7.0 | **php-memcached-dev/php-memcached** | `--with-libmemcached-dir`, `--with-zlib-dir`, sasl/igbinary/msgpack flags; extension-name `memcached` |
| mongodb | mongodb/mongodb-extension | 2.5.5 | php-ext | >=8.1,<9 | **mongodb/mongo-php-driver** | **`download-url-method: pre-packaged-source`**; requires ext-date, ext-json; many `with-mongodb-*` flags |
| mailparse | pecl/mailparse | 3.2.0 | php-ext | >= 7.3 | **php/pecl-mail-mailparse** | no configure-options |
| pcov | pecl/pcov | 1.0.12 | php-ext | >= 7.1 | krakjoe/pcov | `--enable-pcov` |
| msgpack | msgpack/msgpack-php | 3.0.1 | php-ext | >= 7.0 | **msgpack/msgpack-php** | extension-name `msgpack` |
| igbinary | igbinary/igbinary | **3.2.17RC1 only** | php-ext | n/a | igbinary/igbinary | **no stable release**; a stable-only filter finds nothing |
| imap | sirlouen/imap | 1.1.2 | php-ext | **>= 8.3** | SirLouen/pecl-mail-imap | **third-party fork** (about 275 downloads); `--with-imap` prefix, `--with-imap-ssl`, `--with-kerberos`; excludes Windows |
| mcrypt | pecl/mcrypt | 1.0.9 | php-ext | >= 7.2, <= 8.6.0 | php/pecl-encryption-mcrypt | priority 20; dropped by decision |
| ssh2 | none | n/a | n/a | n/a | n/a | **No PIE package on Packagist** (search finds only userland SSH libraries) |
| ldap, sodium | php/ldap, php/sodium | 404 on p2 | n/a | n/a | n/a | bundled in php-src; compiled through `PHPConfigure` only |

Consequences:
- The current rule "GitHub repo name must equal the extension name" would reject redis, memcached, mailparse, msgpack and mongodb. It must become a per-entry allowlisted `owner/repo` (listed above), keeping the dist = source = commit pin.
- A `require.php` check is needed: xdebug 3.5.3 refuses PHP 8.6, mongodb refuses PHP 9, imap needs 8.3+. Today `ResolveExt` ignores it.
- xdebug is the only candidate declared `php-ext-zend`; its directive is `zend_extension=`.
- mongodb needs `pre-packaged-source` (a release asset, because the driver vendors libbson/libmongoc as submodules). The zipball path used for the others does not carry them.

## Candidate list (revised)
Already built: gd, intl, opcache, apcu, imagick.
Packagist, no extra library: redis, xdebug, msgpack, pcov, mailparse.
Packagist, new library: memcached (libmemcached).
Bundled in php-src, new library: sodium (libsodium), ldap (OpenLDAP, SASL).

Bundled in php-src, added 2026-11-01: sockets, pcntl (no library), exif (no library), bz2 (libbz2 built from source).

Decided 2026-11-01:
- Held back: ssh2 (no PIE package), igbinary (RC only). Revisit if a package or stable release appears.
- Dropped: imap (only a young third-party fork), mongodb (needs the pre-packaged-source path).
- **Every optional extension is a build-time checkbox**, including the ones built today (mbstring, curl, zip, mysqli, pdo_mysql, pgsql, pdo_pgsql, soap, bcmath, gmp, gd, intl, dom/simplexml/xml/xmlreader/xmlwriter, sqlite3, pdo_sqlite, opcache). That is 22 existing + 12 new = 34 choosable. The "15" target is superseded.
- Always built, not choosable (nothing to select or others depend on them): openssl, libxml, zlib, ctype, filter, tokenizer, session, fileinfo, pdo, phar.
- Form pre-ticks the selection of the newest build; with no build yet, the 22 existing extensions.
- Composer constraints parsed with a semver library (see Open questions 1).

## PIE logic to port (Go, `internal/phplibs/ext.go`, `internal/phpbuild`)
1. Read the `php-ext` block from the p2 entry: `extension-name` (default: package name without vendor), `build-path` (`{version}` substituted), `configure-options`, `priority`, `support-nts`, `os-families` / `os-families-exclude`, `download-url-method`.
2. Check `require.php` against the PHP version being built; pick the newest release that satisfies it, else refuse that extension for that build. Needs a Composer constraint parser (`^`, `~`, `||`, `,`).
3. Validate our configure flags against the package's declared `configure-options`; an upstream rename then fails at fetch time.
4. Derive `extension=` vs `zend_extension=` from the package type (`php-ext-zend`).
5. Build quirks from `UnixBuild`: rename `config0.m4`/`config9.m4` to `config.m4` when missing, run `phpize` in `build-path`, compare phpize's API version with the target PHP.
6. Do not port: `pre-packaged-source` (only mongodb needed it, now skipped; an entry declaring it is refused), Composer solver, `pie.json`/`pie.lock`, apt/dnf/apk auto-install and sudo, Windows, pre-packaged binaries, ini strategies, bundled `php/*` refusal.

## Functional requirements
1. `/php` build form shows one checkbox per choosable extension, grouped (core, web, db, extra), pre-ticked from the newest build's recorded selection (all 22 existing ones when there is no build). Ticking one auto-ticks what it needs; unticking one that others need is refused with the reason.
1a. Each allowlist entry declares `Needs` (extensions) and `Libs` (source-built libraries), e.g. simplexml/xmlreader/xmlwriter/dom need xml (libxml is always built), gd needs libpng/libjpeg/freetype/libwebp, pdo_mysql and mysqli share mysqlnd, pgsql and pdo_pgsql share libpq, zip needs libzip, intl needs ICU, mbstring needs oniguruma, gmp needs libgmp, bz2 needs libbz2, memcached needs libmemcached, ldap needs OpenLDAP. Fetch and Build take only the union of the ticked set's `Libs`. (Exact dependency edges to be verified against php-src configure during design.)
2. Selection is stored in the job and recorded in the build (e.g. `exts.txt` beside `libs.txt`); the label stays `<ver>-<n>`.
3. `Fetch` downloads only the libraries and PECL sources the selection needs; `Build` compiles only those.
4. `PHPConfigure` emits flags per selection; PECL extensions build via `ExtRecipe` extended with per-extension flags and library deps.
5. `verifyBuild` checks the selected set (not the whole allowlist).
6. The site checklist (`extOpts`) lists only extensions present in the site's build; a site that ticks a missing one is refused with the existing message.
7. Load order and directive type are per extension (priority from the package; xdebug and opcache are `zend_extension`; mailparse after mbstring; serializers before redis/memcached if their support is wanted).
8. Rebuilding the same version with a different selection yields a new `-n` build; old builds untouched.
9. An extension whose latest release does not support the build's PHP branch is shown disabled with the reason, not offered.

## Non-functional
- Same trust model: sha256/GPG where published; PECL at the Packagist commit over HTTPS, commit and zip/asset sha256 logged.
- No free-form strings reach the root build job; names, repos and flags come from the allowlist.
- Build time and disk grow with selection; show the library list before starting.
- Every new library recipe is unit-tested; a real-compile smoke test for at least one library-heavy extension.

## Acceptance
- Build with redis only: `redis.so` exists, `apcu.so`/`imagick.so` do not, ImageMagick not built.
- Site on that build cannot tick imagick (not offered).
- Existing builds (no `exts.txt`) keep working: treated as "everything the allowlist had then".
- Unticked library-heavy extensions never trigger their library download.
- Building PHP 8.6 does not offer xdebug (its `require.php` caps at <8.6).
- A renamed upstream configure option fails the fetch with a message naming it.

## Open questions
Resolved 2026-11-01: ssh2 held, igbinary held, imap dropped, mongodb skipped; all optional extensions become checkboxes; pre-tick the newest build's selection; semver library; sockets, pcntl, exif, bz2 added.

Open for design:
1. Semver library: add `github.com/Masterminds/semver/v3` (go.mod edited by hand per repo rule). Verify it parses the seen forms: `>= 7.0.0`, `>=8.0,<8.6`, `>= 7.2.0, <= 8.6.0`, `>=8.1,<9`. Not yet checked.
2. Existing sites: a site's saved extension list may name something a rebuild no longer contains; the existing `checkBuildHas` refusal covers it, but the build form should warn when unticking an extension some enabled site uses.
3. Making the previously always-shared libraries conditional is a larger change to `PHPConfigure` and `phplibs` than the PECL part: each `--with-*=shared` flag and its library recipe becomes conditional. Verify the dependency edges (`Needs`) against php-src before design.
4. Build-time and disk estimates now vary a lot (a redis-only build skips ICU, ImageMagick, libpq...). Show the library list and a rough estimate on the form?
5. The `exts.txt` record must also carry the PECL versions built, so the next build can show "what changed".
