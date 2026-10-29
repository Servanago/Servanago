# Implementation plan: Postmark mail bridge

Design: `claudedocs/design_postmark_bridge.md`. Scope: `claudedocs/requirements_next_features.md` §2.
Work on branch `postmark-bridge`; fast-forward `main` after `make check`.

## Stage 1: Schema + store
**Goal**: `008_mail.sql` (settings columns, `mail_domains`, `mail_events`, `mail_delivered`), `internal/store/mail.go`, Settings struct carries the new fields.
**Success Criteria**: migration applies on a fresh DB and the old-DB copy path; store round-trips; `TestMigrationsIdempotent` updated for `user_version` 8.
**Tests**: store/mail_test.go — settings save/load with sealed token + lmtp creds; mail domain CRUD; counter bump; events insert/list/cascade; dedupe insert/lookup.
**Status**: Not Started

## Stage 2: Postmark admin client
**Goal**: `internal/postmark/admin.go` — paginated Servers/Domains lists, CreateServer, UpdateServer (hooks + RawEmail + IncludeBounceContentInHook + EnableSmtpApiErrorHooks + InboundDomain), CreateDomain (lazy DKIM), VerifyDkim/VerifyReturnPath, the `{ErrorCode,Message}` error convention.
**Success Criteria**: every call exercised against an httptest stub; error and list-paging covered.
**Tests**: internal/postmark/admin_test.go.
**Status**: Not Started

## Stage 3: mailbridge logic
**Goal**: `internal/mailbridge` — payload structs, decodeRaw (plain → base64 fallback), rebuild-from-fields MIME (ported buildMIME), LMTP client (go-smtp; dial/TLS/auth/timeout), DSN builder (RFC 3464, loop guard), inbound outcome mapping.
**Success Criteria**: decodeRaw handles the verified fixture; LMTP results map 250→ok/4xx→temp/5xx→failed; DSN parses as multipart/report with MAIL-FROM semantics documented.
**Tests**: internal/mailbridge tests — scripted fake LMTP server (conn-level), decodeRaw, buildMIME, buildDSN.
**Status**: Not Started

## Stage 4: Webhook handlers
**Goal**: `/hook/{domain}` and `/events/{domain}` wired on the top mux (no cookie/CSRF), bcrypt auth, limits, dedupe, counters, DSN send.
**Success Criteria**: mapping table (auth→401, domain mismatch→403, LMTP temp→503, LMTP perm→403, deduped→200) with tests; counters correct.
**Tests**: internal/web/mailhook_test.go with fake LMTP conn + seeded store.
**Status**: Not Started

## Stage 5: Provisioning + Mail page + Settings fieldset
**Goal**: provisioning engine (lookup/adopt/create, webhook cred, hooks push, DNS writes via cfdns, InboundDomain, verify-watch loop, counters/notes), `/mail` page template, `POST /settings/mail`, routes, help hints.
**Success Criteria**: form posts provision against stub Postmark + cftest fake; adopt rule honored; DNS notes and states land in DB; page renders complete (per template-test rule).
**Tests**: internal/web/mail_test.go (cftest.Fake + httptest postmark + fake LMTP), page completeness.
**Status**: Not Started

## Stage 6: MCP + docs
**Goal**: six MCP tools via mcpRun, skills/servanago-mail/SKILL.md, docs/mcp.md + new docs page for Mail, llms.txt, README, ROADMAP row.
**Success Criteria**: TestAgentSkillsMatchTheMCPTools and MCP tests pass, all doc surfaces updated.
**Tests**: internal/web/mcp_mail_test.go.
**Status**: Not Started