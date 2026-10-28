# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Brian Tafoya plus a small set of equal administrator accounts he creates, managing Tafoya Ventures hosts (`v1`, `bee`). ServanaGo is public (MIT, GitHub) but built for this admin team's needs first; other self-hosters are welcome users, not the design target. Confirmed 2026-10-28.

## Product Purpose

A lightweight self-hosted web runtime manager: one native host, one binary serving an admin web UI, embedded Caddy for TLS/HTTP, SQLite for state, systemd for app supervision. It manages sites (static, reverse proxy, Node.js, PHP-FPM, FrankenPHP, FastCGI, CGI) with hostnames, certificates, Cloudflare DNS sync, an optional magic-link gate, and an MCP API. Success: standing up and maintaining a site on a real host takes minutes, without the sprawl of a hosting control panel.

## Positioning

Native-host manager, not a multi-tenant control panel: systemd supervises runtimes, a tiny root helper does the privileged work, and Unix-user separation is explicitly not a security boundary for untrusted tenants. Nothing here competes with Plesk/cPanel breadth; the claim is a small, auditable surface a developer can read end to end.

## Operating Context

- Production (`v1`, Ubuntu 24.04) and the developer workstation (`bee`, dpkg package) hold real data; schema changes land as `NNN_*.sql` migrations that apply on start.
- Deploy only when asked; every slice gates on `make check` (lint + Go tests + Playwright e2e) before it reaches `main`.
- The panel runs behind Cloudflare in production with the magic-link gate and Turnstile enabled on the public login.
- A companion project (`gopmstall`) plans a Postmark→LMTP mail bridge that ServanaGo will take over (requirements: `claudedocs/requirements_next_features.md`).

## Capabilities and Constraints

- Stack: Go, Caddy embedded as a library, `modernc.org/sqlite`, Go templates + htmx + Pico CSS via `embed.FS`, no Node build step.
- Hosts must be Debian 12+ / Ubuntu 22.04+ with systemd ≥ 252. No container image in v1.
- Secrets come from env or root-owned files, never SQLite or logs; site secrets are secretbox-sealed.
- Every host/IP/path/domain input passes `internal/config` validators; helper actions are typed and re-validate.
- Admin UI mutations are audited (`audit_log`); MCP mutations audit as the actor "mcp token".
- Explicitly undecided: whether future multi-host or tenancy features arrive (roadmap currently says no).

## Brand Commitments

- Name: ServanaGo. Dark theme with the `--sg-*` token pack (brand greens on dark slate surfaces) is the committed identity; primary action fill is green-800 `#08764B`, accent green-400.
- Avoid side-stripe borders and glow shadows. Logo uses processed `original-concept` PNGs until the SVG mark is re-traced.
- No AI attribution anywhere in commits, docs, or UI copy.

## Evidence on Hand

- `CLAUDE.md` (project conventions, decisions per milestone), `docs/ROADMAP.md`, `DESIGN.md` (inherited architecture record), `claudedocs/*.md` (requirements + design docs per feature).
- Real production deployment and audit data on `v1`; e2e suite in `e2e/`.
- No marketing material, testimonials, or customer evidence exists; none may be fabricated.

## Product Principles

1. Boring and auditable: the admin can read every change's source (audit log, SQLite state, Caddy JSON, unit files).
2. Native host truth: SQLite is desired state; Caddy, DNS, and units converge — never mutate Caddy piecemeal.
3. Small surface: a feature that needs a new subsystem needs a stronger argument than a feature that reuses one.
4. Real-host discipline: migrations, backups, and rehearsals run against production-shaped data before any deploy.

## Accessibility & Inclusion

- The primary operator is dyslexic: favour plain-language copy, consistent label order, and help hints that avoid symbols or clever abbreviations (the help-text test already bans `<`/`>` in hints).
- Known floor: the current form-border contrast (~1.7:1) is a documented gap to fix when touched.
- Dark theme is the only theme; colour is never the sole signal (status pills pair text or dot).