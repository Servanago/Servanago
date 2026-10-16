# M0: fork and rebrand

Baseline on `c1133b3` (Caretakarr head), measured before any change:
- `go test -race ./cmd/... ./internal/...` passes (~4 min)
- `make lint` is clean with golangci-lint v1.64.8 built with Go 1.26 (CI's version; the preinstalled v2 rejects `.golangci.yml`)
- e2e: 27 pass, 1 skipped. In this sandbox it needs the proxy env unset (`env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy`) and a local, git-excluded `e2e/playwright.local.config.ts` pointing at `/opt/pw-browsers/chromium` (installed build 1194, Playwright wants 1248)

## Stage 1: Rename caretakarr -> servanago
**Goal**: Every identifier, path, env var and string says `servanago`; behavior unchanged.
**Success Criteria**:
- Module `github.com/servanago/servanago`; binary `servanago`; image/Dockerfile names updated (Dockerfile stays until Stage 3 decides its fate)
- Env prefix `CARETAKARR_*` -> `SERVANAGO_*` (HOST, HOST_IP, HOST_ZONE, SECRET_KEY); `.env.example`, compose files, e2e config updated
- Caddy module IDs `caretakarr_gate` -> `servanago_gate`, log writer `caretakarr` -> `servanago`; gate cookie `caretakarr_gate` -> `servanago_gate`; CLI `2fa-reset` unchanged
- `rg -i caretakarr` hits only: NOTICE/LICENSE credit lines, the git history note, and assets deferred to Stage 2
- `make test`, `make lint`, e2e identical to baseline
**Tests**: A test asserting the rendered Caddy JSON uses `servanago` module IDs and the log writer name (extend `caddycfg` golden, run `-update` and review the diff); `config` tests for `SERVANAGO_*` names incl. the fail-fast messages naming the variable; existing suites unchanged otherwise.
**Status**: Complete (go test -race, lint and e2e 27/27 match baseline; README hero image path is dangling until Stage 2/4; `caretakarr-assets/` untouched until Stage 2)

## Stage 2: Brand assets and theme
**Goal**: UI shows ServanaGo identity.
**Success Criteria**:
- `caretakarr-assets/` removed from the tree; pack's `original-concept` PNGs (logo, favicon set, web/PWA icons) and tokens added under `internal/web/static/`
- `caretakarr.css` replaced by `servanago.css` built from `--sg-*` tokens, mapped onto Pico via `:root[data-theme="dark"]`; primary buttons use green-800 `#08764B`
- Favicon/touch icons wired in `layout.html`; page titles say ServanaGo
- No side-stripe borders or glow shadows
**Tests**: e2e login/dashboard/sites specs pass; a Go test that every asset the layout references exists in the embed FS; screenshot of login and dashboard reviewed by eye.
**Status**: Complete. Notes:
- Stage 1 missed the topbar/login wordmark (`Care<b>takarr</b>`, split by a tag); fixed here and now pinned by `TestTemplatesUseBrandAndExistingStatics`
- The pack's original-concept icon PNGs are opaque (baked light surround) and the 512px one is cropped; the icon panel is the only complete tile. Icons are derived from it by `docs/brand/keyout.py` (see `docs/brand/README.md`). The wordmark PNG ships unmodified for the README only
- Dark-surface contrast: pack slate-500 muted text and the success/danger/info semantics fail AA on the dark UI; the theme uses lifted variants, pinned by `TestThemeMeetsContrast`
- Not done (out of scope): form field borders (`--sg-border` on `--sg-bg`) are ~1.7:1, as in the inherited theme; WCAG 1.4.11 wants 3:1 for input boundaries

## Stage 3: Prune arr-stack features
**Goal**: Remove code that has no place in a hosting manager; nothing else changes.
**Success Criteria**:
- `internal/discovery`, `internal/presets`, `docker.html`, `DOCKER_SOCKET`, docker e2e spec and UI hooks removed; preset field removed from forms and help text
- Migration `006` drops `routes.preset` only if safe on SQLite (otherwise leave the column unused and document it)
- Dockerfile/compose: decision recorded (native-only v1 means they go; keep nothing that implies container mode)
- `make check` green; dependency list does not grow
**Tests**: existing suites minus deleted ones; `help_test.go` still passes (no dangling hints); migration test from a v5 DB with data.
**Status**: Not Started

## Stage 4: Docs and release plumbing
**Goal**: Repo describes Servanago as a lightweight runtime manager.
**Success Criteria**:
- README, `llms.txt`, `docs/REQUIREMENTS.md`, `docs/DESIGN.md` reframed (no "arr stack"; native-only, Phase 0 decisions, milestone list); NOTICE keeps all third-party credits
- CI workflow renamed; image job removed (native-only); tag flow documented
- `IMPLEMENTATION_PLAN.md` for M1 written; this file deleted
**Tests**: `make check` green on a clean clone.
**Status**: Not Started
