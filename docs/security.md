# Security and access

## `UI_LISTEN` is a recovery hatch

The UI listens on loopback and Caddy proxies `SERVANAGO_HOST` to it. If Caddy is broken you can set `UI_LISTEN=0.0.0.0:8080` to fix things, but then the UI is reachable without TLS. With no administrators that is a full authentication bypass. Remove it again afterwards.

## Administrators

Everyone who can sign in is an administrator with the same powers; there are no roles. The **Users** page adds and removes administrators, sets their passwords and resets their second factor. Each of those:

- asks for your own password again (and a code, if you use an authenticator);
- ends the other person's open sessions;
- cannot be done to yourself or to the last administrator.

Every action is recorded on the **Audit** page (who, what, target, client address; never a password or code).

Locked out? Run `servanago user passwd NAME` (or `user add NAME`) on the server; it reads only `DATA_DIR`.

## Two-factor and passkeys

The Security page adds an authenticator app (with 10 one-time backup codes) and passkeys, for the signed-in administrator only. A passkey sign-in skips the code.

- Passkeys work on `https://SERVANAGO_HOST` and on `localhost`, and are tied to that hostname: changing `SERVANAGO_HOST` makes existing ones unusable.
- Lost an authenticator and passkeys? Another administrator can reset them on the Users page, or run `servanago 2fa-reset NAME` on the server (needs only `DATA_DIR`). It removes that person's authenticator, backup codes and passkeys and ends their sessions.
- `REQUIRE_2FA` and Turnstile are in [Configuration](configuration.md).

## Magic-link site access

A site's form can require a magic link before the site is served: either an allowlist of addresses and `@domains`, or open to any address. The link is sent by email, single use, valid 15 minutes.

- **Mail provider per site**: SMTP (host, port, user, password) or the Postmark HTTP API (server token), plus a sender address. The credential is stored encrypted, which needs `SERVANAGO_SECRET_KEY`. The Settings SMTP account is not used for this.
- **Host**: the link opens on `ml.` in front of the site's main hostname (ServanaGo creates its Cloudflare records and certificate), which hands the visitor to the site. Other hostnames of the site redirect to the main one. Gating therefore needs Cloudflare.
- **Access list**: rows on the site's page, added and removed one at a time.
- **With an IP allowlist**: either one gets in. Listed networks skip the link; every other address is asked for one.
- **Sessions**: shared across the gated sites that allow that address; they slide 30 days (allowlist) or 7 days (open) while in use. Revoking one identity under Security cuts it on every gated site at once.

This is an access barrier for staging sites, not full authentication. A site that needs real auth must do its own.

## Isolation

Unix-user separation is not a sandbox for mutually untrusted tenants. Do not host mutually untrusted sites on one host.

## Data directory

The user running ServanaGo must be able to write `DATA_DIR` (the database and Caddy's certificate storage). Keep it private to that user.

## PHP builds

What is verified and what is trusted: see [PHP built from source](php.md#what-is-verified-and-what-is-trusted).
