---
name: servanago-setup
description: Install, configure, upgrade and recover a ServanaGo host, including enabling its MCP endpoint. Use when asked to install ServanaGo from the .deb, edit /etc/servanago/servanago.env, set SERVANAGO_MCP_TOKEN, SERVANAGO_MCP_PUBLIC or SERVANAGO_MCP_ALLOWLIST, upgrade to a new release, or recover a locked-out administrator.
---

# ServanaGo host setup

Requires ServanaGo 0.9.0 or newer.

This is for the operator of the host. Debian 12+ / Ubuntu 22.04+ with systemd 252+, installed from the release `.deb`. There is no container image. Privileged commands below need root; run them only on the host the user names, and confirm before anything that restarts services.

## Install

1. Download `servanago_<version>_amd64.deb` from the GitHub releases of Servanago/Servanago and compare its sha256.
2. `sudo apt-get install ./servanago_<version>_amd64.deb`
3. Edit `/etc/servanago/servanago.env` (a conffile; dpkg keeps your edits): at least `SERVANAGO_HOST`, `ACME_EMAIL`, `ADMIN_PASSWORD`.
4. `sudo systemctl start servanago`, then open `https://<SERVANAGO_HOST>`. The unit is enabled but not started by the package.

Cloudflare is optional (`CLOUDFLARE_API_TOKEN`, `SERVANAGO_HOST_IP`); without it certificates use HTTP-01, so ports 80 and 443 must be reachable. `SERVANAGO_SECRET_KEY` (32+ characters, `openssl rand -hex 32`) is needed for the authenticator app and the magic-link gate; back it up with the data directory.

## Enable the MCP endpoint

Set in `/etc/servanago/servanago.env`, then `sudo systemctl restart servanago` (read at start only):

- `SERVANAGO_MCP_TOKEN`: 32+ characters (`openssl rand -hex 32`). Unset means `/mcp` does not exist. Whoever holds it can create, change and delete sites; keep it out of chat, logs and git.
- `SERVANAGO_MCP_PUBLIC` (default `false`): `true` lets `/mcp` answer through the public hostname. Off, only the local `servanago mcp` stdio relay works and the public URL answers 404.
- `SERVANAGO_MCP_ALLOWLIST` (optional, comma-separated IPs or CIDRs): with PUBLIC on, only these remote addresses reach `/mcp`, checked before the token. Empty means any address.

Clients and tools: `servanago-mcp`.

## Upgrade

1. Copy the new `.deb` to the host and compare sha256.
2. Do not upgrade while a PHP build runs (the install watcher dies on restart).
3. `sudo systemctl stop servanago servanago-helper`
4. Back up the database: `sudo cp -p /var/lib/servanago/servanago.db /var/lib/servanago/servanago.db.pre-<version>`
5. `sudo dpkg --force-confold -i servanago_<version>_amd64.deb` (keeps your env file; new env options then need adding by hand)
6. `sudo systemctl daemon-reload`, start `servanago-helper`, then `servanago`.
7. Verify: both units active, `journalctl -u servanago`, `/login` answers 200. Migrations apply on start.

## Locked out

Another administrator resets you on the Users page. On the server, with only `DATA_DIR` needed: `servanago user passwd NAME`, `servanago user add NAME`, `servanago 2fa-reset NAME`.

## Troubleshooting

- `permission denied` on the data directory: it must be writable by the `servanago` user.
- Certificate never issues: check the token scopes (`Zone:Zone:Read`, `Zone:DNS:Edit`), try `ACME_STAGING=true`. A failed DNS-01 attempt can leave `_acme-challenge` TXT records that block the next issuance; delete them.
- MCP 404: token unset, or a remote request without `SERVANAGO_MCP_PUBLIC=true` / outside the allowlist.
