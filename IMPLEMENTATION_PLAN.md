# M2.5: multi-admin

Decisions (settled in discussion; no deployed installs, so no migration or compatibility code):
- Equal admins: no roles. Any admin can add and remove admins, set other admins' passwords and reset their second factors.
- Login is username + password. Passwords are bcrypt hashes in SQLite (min 8 bytes, max 72; the env seed is exempt from the minimum).
- `ADMIN_PASSWORD` (and optional `ADMIN_USER`, default `admin`) creates the first admin when the users table is empty, then is ignored. No users and no `ADMIN_PASSWORD` keeps today's open mode with its banner. The last admin cannot be deleted, so the UI never falls back to open.
- Sessions are signed cookies carrying user id and a per-user epoch, checked against the DB on every request. Deleting a user, changing a password or resetting 2FA bumps the epoch and ends that user's sessions.
- TOTP, backup codes and passkeys are per user. `REQUIRE_2FA` applies to each user. WebAuthn user handle is a random per-user id.
- Recovery without a session: `servanago user passwd <name>` and `servanago 2fa-reset <name>`, reading `DATA_DIR` only.
- Audit: a persisted `audit_log` table (time, actor, action, target) written by every state-changing admin handler, with a read-only Audit page. Site-visitor gate sessions stay unrelated and global.

## Stage 1: users, sessions, login
**Goal**: `users` table; first admin seeded from env; login takes a username; session cookie carries user id and epoch and is validated per request; the request carries its user; open mode iff no users.
**Success Criteria**: existing flows (password login, TOTP, passkeys, enroll-only sessions) still work for the seeded admin; deleting a user or bumping the epoch kills its sessions; unknown usernames cost the same time as wrong passwords; the last admin cannot be deleted.
**Tests**: store (create, case-insensitive unique name, password set bumps epoch, last-admin guard); web (login with and without username, wrong user, epoch bump invalidates a cookie, seeding once, open mode); existing auth tests moved to the username field.
**Status**: Complete (built and committed together with Stage 2). The per-request user lookup validates uid and epoch; an unknown username burns one bcrypt comparison and gets the same answer as a wrong password; `ADMIN_USER` is validated; the "REQUIRE_2FA needs ADMIN_PASSWORD" config rule is gone because users live in the DB. Login throttling stays per client IP only: a per-username bucket would let anyone lock an admin out.

## Stage 2: per-user second factors
**Goal**: `totp`, `backup_codes` and `passkeys` keyed by `user_id`; the TOTP step, re-auth, passkey ceremonies and the Security page work on the signed-in user; discoverable passkey login resolves the user from the WebAuthn handle; `REQUIRE_2FA` enrolls per user.
**Success Criteria**: two admins hold independent authenticators, backup codes and passkeys; one's TOTP step or backup code never works for the other; resetting one leaves the other intact.
**Tests**: store per-user isolation; web two-user login with TOTP, backup code reuse across users refused, passkey login picks the right user; enroll-only per user.
**Status**: Complete. `servanago 2fa-reset <username>` (CLI, one user, ends their sessions) landed here because the old no-argument form no longer made sense; `user add` and `user passwd` follow in Stage 3.

## Stage 3: user management and recovery
**Goal**: Users page (list, add, remove, set password, reset 2FA for any admin, with confirmation), change-own-password on Security, and the CLI `user add`, `user passwd`, `2fa-reset <name>`.
**Success Criteria**: an admin can onboard and offboard another admin without a shell; removing or resetting a user ends their sessions; CLI recovers a locked-out last admin using only `DATA_DIR`.
**Tests**: web handler tests for each action and for the guards (last admin, self-delete); CLI tests with a temp DB; help text defined for every new hint.
**Status**: Complete. `/users` (list with each admin's factors; add, set password, reset second factor, remove) and a Password card on Security; both go through one handler, so changing your own password reissues this browser's session while other devices are signed out. Every action re-authenticates the acting admin (own password, plus a code when they have an authenticator), because a stolen session must not be able to mint a second way in. You cannot remove yourself or reset your own factors from `/users`; the last-admin guard lives in the store. Passwords are 8-72 bytes (`config.ValidatePassword`). CLI: `servanago user add NAME` and `user passwd NAME` read the password from a no-echo prompt or one line on stdin and need only `DATA_DIR`.

## Stage 4: audit log
**Goal**: `audit_log` table and `store.Audit`; every mutating admin handler records actor, action and target (sites, domains, settings, users, security changes, logins and logouts); Audit page lists the latest entries.
**Success Criteria**: each action above leaves exactly one row with the acting username; failed logins are recorded with the attempted username and IP; no secret, code or token is ever written.
**Tests**: one table-driven web test per action family asserting the row; page renders and escapes values; retention is capped.
**Status**: Complete. `store.AddAudit`/`ListAudit` (capped at 10,000 rows, trimmed in the same transaction) and `Server.audit`/`auditAs`, which clean control characters and bound the text; a database error is logged, never fatal. Recorded: login (target = method) and login.failed (actor = the name typed, or `unknown` for passkeys), logout, reauth.failed, site created/updated/deleted/toggled/dns_resynced/dns_taken_over, host DNS, domain added/updated/deleted, settings.smtp, user added/password/2fa_reset/removed, totp enabled/disabled, backup codes regenerated, passkey added/removed, gate revoked; the CLI writes rows with actor `cli`. Rows are written after the action succeeds. The Audit page (`/audit`, latest 200) is behind the normal session gate, so it works in open mode too.

## Stage 5: docs and e2e
**Goal**: README, llms.txt, help text and DESIGN updated; Playwright specs for two admins and the Users and Audit pages in both projects.
**Success Criteria**: `make check` green; README install steps still work from an empty data directory.
**Tests**: e2e (second admin created, signs in, is removed and loses the session; audit page shows the actions); `help_test` for new hints.
**Status**: Not started
