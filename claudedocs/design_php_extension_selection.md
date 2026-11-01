# Design: build-time PHP extension selection

Status: design, 2026-11-01. Inputs: `requirements_php_extensions.md` (settled list, PIE findings). Not implemented.
Reference checks: Context7 for Masterminds/semver and php-src/manual (cited inline). Anything not checked is marked **unverified** and has a test that settles it.

## 1. Shape of the change

Today the extension set is fixed: `runtimes.PHPExtensions` (22 entries), `PHPConfigure` hard-codes every `--with-*=shared` flag, `phplibs.Names()` builds every library, `ExtNames()` fetches apcu+imagick. A build is `Job{Version,N,Jobs}`.

After: the job carries a **selection**. Everything downstream is derived from it.

```
/php form (checkboxes, pre-ticked from newest build)
  -> web phpBuild: close selection (add Needs), validate against registry
  -> helper PHPBuild: re-validate, write job.json{version,n,jobs,exts[]}
  -> fetch job: libs = union(Libs of exts) ; PECL = exts with Source=pecl
  -> build job: PHPConfigure(version, prefix, deps, exts) ; PECL recipes
  -> writes <prefix>/exts.txt  (what was built, PECL versions)
  -> helper verifyBuild: expects exts.txt set, not the whole allowlist
  -> runtimes detect reads exts.txt -> site checklist offers only those
```

No DB migration: the selection lives in `job.json` and `exts.txt`; "remember last" reads the newest build's `exts.txt`.

## 2. Registry (single source of truth)

Replace `runtimes.PHPExtensions []Ext` with a richer entry. Same package, so `ParseExtensions`, `SharedExtensions`, `Directive`, `extOpts` keep working.

```go
type Ext struct {
    Name   string
    Group  string   // core | web | db | extra  (form grouping)
    Zend   bool     // zend_extension= (opcache, xdebug)
    Source Source   // Bundled | PECL
    Needs  []string // other choosable extensions that must be ticked too
    Libs   []string // source-built libraries (phplibs names) this extension links
    Flag   []string // bundled: configure args; PECL: extra args (see 5)
    MaxDep string   // optional human note, not logic
}
```

Per-extension data. **Verified 2026-11-01** against php-src `PHP-8.4` and `master` `ext/*/config.m4` (raw files) and the PECL repos' `config.m4`/module sources: no bundled choosable extension has a hard dependency on another choosable one. The only `PHP_ADD_EXTENSION_DEP` edges are to always-built modules (pcre, date, spl, hash, libxml, mysqlnd, pdo, lexbor) or are optional (`xmlreader`->dom, `soap`->session, `exif`->mbstring on master: load-order hints only). So `Needs` is empty for every bundled entry; the registry order (dom before xmlreader, mbstring before exif and mailparse) already gives the ini load order.

| Ext | Source | Needs | Libs | Configure / notes |
|---|---|---|---|---|
| mbstring | bundled | | oniguruma | `--enable-mbstring=shared`; libonig found by pkg-config since 7.4 (manual, Context7) |
| opcache | bundled | | | zend; shared only < 8.5 (existing `Shared()`) |
| sqlite3 | bundled | | sqlite | `--with-sqlite3=shared` |
| pdo_sqlite | bundled | | sqlite | `--with-pdo-sqlite=shared`; depends only on pdo (always built) |
| dom, simplexml, xml, xmlreader, xmlwriter | bundled | | (libxml2 always built) | `--enable-X=shared` |
| curl | bundled | | curl | `--with-curl=shared` |
| zip | bundled | | libzip | `--with-zip=shared` |
| gd | bundled | | libpng, libjpeg-turbo, freetype, libwebp | `--enable-gd=shared --with-jpeg --with-freetype --with-webp` |
| intl | bundled | | icu | `--enable-intl=shared` |
| soap | bundled | | | libxml, date, hash always built; session optional |
| bcmath | bundled | | | |
| gmp | bundled | | gmp | `--with-gmp=shared,<prefix>` |
| mysqli, pdo_mysql | bundled | | | `--with-mysqli=shared,mysqlnd`, `--with-pdo-mysql=shared,mysqlnd`; mysqlnd is the only driver (php-src `ext/mysqli`, `ext/pdo_mysql` config.m4, Context7) and needs openssl, always built |
| pgsql, pdo_pgsql | bundled | | libpq | |
| **sockets, pcntl** | bundled | | | `--enable-sockets=shared`, `--enable-pcntl=shared`; pcntl is CLI/FPM-useful, Unix only (manual) |
| **exif** | bundled | | | `--enable-exif=shared`; no library; mbstring is an optional ordering dep (master config.m4, manual): mbstring must load first when both are on |
| **bz2** | bundled | | bzip2 | `--with-bz2=shared,<prefix>` (`--with-bz2[=DIR]`, verified) |
| **sodium** | bundled | | libsodium | `--with-sodium` takes **no DIR** (verified: `AS_HELP_STRING([--with-sodium]`); found by pkg-config, so `PKG_CONFIG_PATH` from `BuildEnv` is the mechanism, `--with-sodium=shared` |
| **ldap** | bundled | | openldap | `--with-ldap[=DIR]` and a separate `--with-ldap-sasl` (verified); `--with-ldap=shared,<prefix>`, SASL left off |
| apcu | pecl `apcu/apcu` | | | `--enable-apcu` |
| imagick | pecl `imagick/imagick` | | imagemagick (+ png, jpeg, webp, freetype) | `--with-imagick=<prefix>` |
| redis | pecl `phpredis/phpredis` | | | extension-name `redis`; serializer/compression flags left off |
| xdebug | pecl `xdebug/xdebug` | | | type `php-ext-zend`; refuses PHP >= 8.6 |
| msgpack | pecl `msgpack/msgpack-php` | | | flag is `--with-msgpack` (not `--enable-`; verified in its config.m4); the feed declares no `configure-options`, so the flag guard in 5 must accept a flag the feed omits only when the registry marks it `ImplicitFlag` |
| pcov | pecl `pecl/pcov` | | | `--enable-pcov`; config.m4 chooses a CFG version file by PHP version, no flag |
| mailparse | pecl `pecl/mailparse` | mbstring | | the manual says mbstring is required and must load first; the source and config.m4 declare no dependency (grep found none), so this is a runtime ordering rule, enforced by `Needs` plus registry order |
| memcached | pecl `php-memcached/php-memcached` | | libmemcached (+ zlib) | `--with-libmemcached-dir=<prefix> --with-zlib-dir=<prefix>`; sasl/igbinary/msgpack flags left off |

Always built, not choosable: openssl, libxml, zlib, ctype, filter, tokenizer, session, fileinfo, pdo, phar.

**Closure rule:** `Close(sel)` = sel plus transitive Needs, in registry order. Web closes before calling the helper; the helper rejects an unclosed or unknown set. Unticking something others need is refused in the form with the reason.

## 3. Job and state

`phpbuild.Job` gains `Exts []string` (registry names, already closed). Written by the helper; the fetch and build units read it. `PHPBuild`'s `Spec` gains `PHPExts []string`.

`plan.json` records the resolved plan: libs (existing) and PECL sources (existing `planExt`) — only for the selection.

## 4. Fetch phase

1. PHP tarball: unchanged (sha256 + GPG).
2. Libraries: `phplibs.Resolve` only for `UnionLibs(exts)` (dependencies of libs first: `libpng` needs zlib, etc.; keep the existing build order in `names`, filter by need). Reuse of installed libs is unchanged.
3. PECL: for each ticked PECL extension, `ResolveExt(ctx, get, name, phpVersion)` (section 5). Failure for any ticked extension fails the whole fetch closed, naming the extension and why. No partial build.

## 5. PECL resolution v2 (`phplibs/ext.go`)

Keep: p2 fetch, minified expansion (`expand`), stable filter, the dist = source = commit pin, GitHub zipball regex, sha256 logging. Change:

- **Per-entry source table** replaces `extPackages` plus the repo-name rule:
  `{Name, Package, Repo "owner/repo"}`; the zipball's `owner/repo` must equal `Repo` (case-insensitive). Repos from the 2026-11-01 feed fetch: `krakjoe/apcu`, `Imagick/imagick`, `phpredis/phpredis`, `xdebug/xdebug`, `msgpack/msgpack-php`, `krakjoe/pcov`, `php/pecl-mail-mailparse`, `php-memcached-dev/php-memcached`.
- **PHP constraint:** choose the newest stable release whose `require.php` is satisfied by the build's PHP version. Parse with `github.com/Masterminds/semver/v3` (`NewConstraint`, `Check`). **Verified:** `go.mod` already lists `github.com/Masterminds/semver/v3 v3.5.0 // indirect`, so no new module: remove the `// indirect` marker by hand. A scratch test (go 1.26, v3.5.0) passed for `>= 7.0.0`, `>=8.0,<8.6`, `>= 7.2.0, <= 8.6.0`, `>=8.1,<9`, `>= 5.6.0`, `>= 8.3.0`, `^7.4 || ^8.0` and `>=7.0 <9`, including the space after the operator and the boundary cases (8.6.0 fails `<8.6`, 9.0.0 fails `<9`, 8.6.1 fails `<= 8.6.0`). Prerelease PHP versions fail a plain constraint (fine: only stable PHP is built). Put the same table in the real test.
- Iterate releases newest to oldest; the first satisfying one wins. None: error `xdebug: no release supports PHP 8.6 (newest 3.5.3 requires >=8.0,<8.6)`.
- **`php-ext` block:** read `extension-name` (must equal the registry name), `build-path`, `support-nts` (must not be false), `os-families`/`os-families-exclude` (linux must pass), `download-url-method` (anything but `composer-default` or absent is refused). `type` `php-ext-zend` must agree with the registry's `Zend`; mismatch fails fetch.
- **Flag guard:** every `--enable-*/--with-*` in the registry's PECL args must appear in the package's declared `configure-options` (xdebug declares none, so it takes no flags). An upstream rename fails fetch with the flag name.
- `ExtSource` gains `Php string` (the constraint), `BuildPath string`.

## 6. New libraries (`phplibs`)

New recipes in `recipe.go`. **Checked 2026-11-01 (release listings):** none of the four publishes a sha256 file. bzip2 (sourceware.org/pub/bzip2/, newest 1.0.8) offers a `.sig`; libsodium (download.libsodium.org, newest listed 1.0.22-stable) offers `.minisig`; OpenLDAP (openldap-release/, newest listed 2.7.2) offers `.asc`; libmemcached (`awesomized/libmemcached`, 1.1.4) has a GitHub tag with **no release assets**. This is exactly the case the existing `pinned` table exists for ("projects that publish no sha256 in any feed"): all four go in `pinned`, each entry downloaded over https once at dev time and checked against the project's own signature before the sha256 is recorded. A newer release needs a code change, as for libpng/freetype/libwebp today.

| Lib | For | Notes |
|---|---|---|
| bzip2 | bz2 | plain `make`, `make install PREFIX=<prefix>`; build the shared lib (`Makefile-libbz2_so`) since PHP links `libbz2.so` (recipe flags **still to be proven** by the real-compile smoke) |
| libsodium | sodium | autotools `std()` |
| libmemcached | memcached | use the `awesomized` fork (the original is dormant); cmake or autotools per its tag, recipe to be proven in the smoke build |
| openldap | ldap | autotools, client libraries only (`libldap`, `liblber`), `--without-cyrus-sasl`, no slapd; flags to be proven in the smoke build |

SASL is deliberately left out of v1 (a second library chain for rare use). Note it in the form's help text.

Library selection: `phplibs.Needed(libs []string) []string` returns the named libraries plus their own dependencies (existing implicit order), used by Fetch and Build instead of `Names()`.

## 7. `PHPConfigure(version, prefix, deps, exts)`

Becomes a loop: fixed base args (prefix, fpm, openssl, libxml, zlib, disables) plus each ticked bundled extension's `Flag` with the library prefix substituted (`deps[...]`). gd keeps `--with-jpeg --with-freetype --with-webp` only when gd is ticked. mysqlnd arises from mysqli/pdo_mysql flags. opcache flag only when ticked and branch < 8.5. Pure and golden-tested (existing pattern), one golden for the full 22 set (must equal today's output: the no-behavior-change anchor) and one minimal.

## 8. Build phase, record, verify

- Build compiles only the planned libs, then PHP, then each PECL extension through `ExtRecipe` (reads args from the registry; `phpize` runs in `build-path` when set; add the `config0.m4`/`config9.m4` -> `config.m4` fallback from PIE's `UnixBuild.renamesToConfigM4`).
- After success, write `<prefix>/exts.txt`: one line per extension, `name` for bundled and `name version commit` for PECL. Atomic write before `PhaseBuilt`.
- `verifyBuild` (helper): expected = `exts.txt` names that are shared in this branch; missing `.so` fails. No `exts.txt` (a build from before this change) = legacy: expect `SharedExtensions(branch)` exactly as today.
- `checkBuildHas` (site save): compares the site's ticks with the build's `exts.txt` set (legacy: as today). Same error text.

## 9. Web and site side

- `/php` build card: grouped checkbox list. Pre-tick = newest build's `exts.txt` (all 22 pre-existing when none). opcache hidden for PHP >= 8.5. Unavailable PECL entries shown disabled with the reason (section 10). JS auto-ticks Needs; the server does not rely on it.
- A summary under the list: libraries that will be built (from `UnionLibs`) so the cost is visible. No time estimate in v1.
- Warning when unticking an extension that an enabled site on this branch has ticked (`ListSites`; no schema change).
- Site form `extOpts`: offer only extensions present in the site's chosen build (`runtimes.PHPVersion` gains `Exts []string` filled from `exts.txt` by detection; empty/legacy = all shared). Default ticks for a site with none chosen stay `CoreExtensions`, restricted to what the build has; if the build lacks one, the site form shows the existing refusal on save.
- MCP: **checked** — there is no PHP-build MCP tool; the only extension touchpoint is the site's `php_ext` in `formOf` (`internal/web/mcp.go:167`), which keeps working because site ticks are unchanged. `runtime_report` lists PHP builds; extend it to show each build's extension set. Update `docs/sites.md`, `docs/mcp.md`, `llms.txt`, `skills/servanago-sites/SKILL.md`, help text (`help.go`) per the repo checklist.

## 10. Availability for the form (no network at render)

The existing PHP release check (`runPHPCheck`, stored in `settings.php_check_json`) is extended to also resolve each PECL entry once per refresh and store `{ext: {version, php}}` inside that JSON. No migration (it is a JSON blob). The form disables an extension whose stored `php` constraint excludes the branch being built, with the text from section 5. Fetch re-resolves live, so a stale cache can only make the form optimistic, never wrong.

## 11. Compatibility and safety

- Old builds keep working untouched (legacy `exts.txt` absence path).
- Names, repos, flags and libraries all come from the registry; nothing free-form reaches the root-owned job or the helper. `FuzzUnitInstallNoInjection` is unaffected; add a helper fuzz for `PHPExts` (unknown, duplicate, traversal-looking, over-long list).
- Trust: unchanged. Bundled via the verified PHP tarball; PECL at the Packagist commit over HTTPS, commit and zip sha256 logged; libs by feed checksum or pinned table.
- Build unit sandbox unchanged (no network in Build). `MemoryMax=4G` may need review for ICU + ImageMagick + OpenLDAP combined; unchanged because the selection can only reduce work vs today, except the four new libraries.

## 12. Tests

1. **Configure smoke (guards the verified dependency table):** for each registry extension alone, run only `./configure` (no make) against an unpacked PHP source with the base args plus that extension's flag; a failing configure means the table drifted. Build tag `smoke`, like `SmokeRealBuild`; run when the registry or a PHP branch changes.
2. `Close` and `ParseExtensions`: table tests, including unknown, duplicates, 8.5 opcache.
3. `PHPConfigure` goldens: full set equals today's args byte for byte; minimal; one mid set.
4. `ResolveExt` v2 table: php constraint choose-newest-satisfying, none satisfying, repo mismatch, type mismatch, undeclared flag, `support-nts:false`, bad `download-url-method`; recorded feed fixtures from the 2026-11-01 fetch (copy into testdata).
5. Semver forms table: the four seen constraint strings against PHP 8.4.27, 8.5.2, 8.6.0.
6. `Fetch`/`Build` with fakes (existing `Env` seams `Libs`, `Exts`, `Run`): a redis-only plan downloads no libs; ticking gd downloads exactly its four libs; unticked PECL never fetched; fail-closed leaves no `plan.json`.
7. `verifyBuild` and `checkBuildHas` with and without `exts.txt`.
8. Web: build form renders every group and pre-ticks from the newest build; posting an unclosed set is closed server-side; unticking a needed extension is refused; template-complete assertion (`>Save</button>` style) for the page.
9. Helper fuzz for `PHPExts`; mutate-the-guard once per the repo rule.
10. Live: one real compile with a representative selection (redis + memcached + sodium) via the existing `SmokeRealBuild` command.

## 13. Stages (each a branch slice, `make check` between)

1. Registry + `Close` + `Job.Exts` + form checkboxes, default = all 22, `PHPConfigure` loop. **Goldens prove no change.**
2. Conditional libraries (`Needed`) and per-extension flags for the existing 22.
3. `exts.txt` write, `verifyBuild`/`checkBuildHas`/detection read it; legacy path.
4. PECL v2 (semver, repo table, `php-ext` checks); apcu/imagick moved onto it.
5. Add bundled: sockets, pcntl, exif (no libs), then bz2 (+ bzip2 recipe).
6. Add libs and extensions: sodium, ldap, then PECL redis, xdebug, msgpack, pcov, mailparse, memcached (+ libmemcached).
7. Availability cache in `php_check_json`, form disables, docs/help/MCP/skill updates, real-compile smoke.

## 14. Risks and open items

- **Verified 2026-11-01:** extension dependency edges (php-src 8.4 and master, PECL sources); semver constraint forms and that semver is already in `go.mod`; no sha256 for the four new libraries (so they are pinned); no PHP-build MCP tool; sodium takes no DIR; msgpack's flag is `--with-msgpack`.
- **Still unproven (cannot be settled by reading):** the compile recipes and flags for bzip2 (shared lib), libmemcached and OpenLDAP, the exact pinned sha256 values, and that redis/memcached link cleanly with serializer flags off. The real-compile smoke (12.10) is the check; none blocks stages 1-4.
- openldap and libmemcached are the most likely to fail on build flags; keep them last (stage 6) so the rest ships first.
- The PECL flag guard (5) must tolerate flags the feed omits when the registry marks them (`msgpack --with-msgpack`; xdebug declares none), else those two fail fetch.
- mailparse's mbstring requirement is documented in the manual but absent from its source: if the manual is wrong, `Needs` is merely conservative.
- 34 checkboxes is a long form; grouping and collapse of the `core`/`web`/`db` groups is a UI detail for implementation.
- `ssh2`, `igbinary` (held) and `imap`, `mongodb` (dropped) are out; adding one later is a registry entry plus, for mongodb, a `pre-packaged-source` path that this design refuses.
