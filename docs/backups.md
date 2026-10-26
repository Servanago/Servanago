# Backups and restore

## Backups page

A scheduled job running as root writes one passphrase-encrypted archive (tar, zstd, age) per opted-in site and one for the panel (database, certificates, secret key) into a folder on the server.

- Retention: keep-newest-N plus weekly.
- Typed database dumps: SQLite, and MariaDB or PostgreSQL inside a container. Passwords never appear on a command line.
- Opt-in container volumes.
- Failures raise a banner, an audit row and an optional ntfy push.

**Copy archives off the server.** They live on the same disk.

### Restoring a site

From the UI, with the password re-checked and the current state backed up first. A restore covers the site's files, its database dumps and its container volumes (a volume restore stops the running containers that mount the volume, empties and refills it, and starts them again). You can also download an archive.

The MCP endpoint has `backup_status`, `list_backups`, `run_backup`, `plan_restore` and `restore_site`; the restore needs the site's short name as `confirm`.

### Restoring the panel

Only from the command line, never from the UI or MCP, with the service stopped:

```sh
servanago backup restore --panel ARCHIVE --passphrase-file FILE
```

CLI commands: `servanago backup list|verify|run|restore`.

Without ServanaGo, any archive opens with `age -d` and the passphrase, then `zstd -d | tar x`.

## What carries state

- `DATA_DIR` (`/var/lib/servanago`): `servanago.db` (every site, user, passkey and sealed secret), `caddy/` (certificates and the ACME account) and `caddy-last-good.json`. Take a consistent copy of the live database with `sqlite3 /var/lib/servanago/servanago.db ".backup /backup/servanago.db"`; a plain `cp` of a running database can miss the `-wal` file.
- `/etc/servanago/servanago.env`: holds `SERVANAGO_SECRET_KEY`. Without that exact key the authenticator seeds, the SMTP password and sealed site secrets in the database cannot be read. Keep it somewhere other than the database backup.
- Your sites' own files (their roots) are only backed up for sites you opt in on the Backups page.
- `/opt/servanago/php` (PHP builds and their libraries, hundreds of MB each) is rebuilt rather than restored; the database keeps which build or branch each site and each user's default PHP uses.

## Manual restore

On the new or repaired host:

1. Install the package, then `systemctl stop servanago`.
2. Put the `.env` back.
3. Copy `servanago.db` (and `caddy/`, to keep certificates and avoid re-issuing) into `DATA_DIR`, owned by `servanago` with mode 0600/0750. Check `PRAGMA integrity_check` on the copy first.
4. Delete any stale `servanago.db-wal` and `-shm`.
5. `systemctl start servanago`.

Sites, users and domains return at once, and proxy and static sites serve again. Node, PHP, FrankenPHP and CGI sites need their unit and system user back: open each one and save it. (Unit files live in `/etc/systemd/system/servanago-<slug>.*` and `/etc/servanago/fpm/`, so a restore on the same host that kept `/etc` needs nothing.) The shims and per-user PHP defaults are written again when ServanaGo starts. A passkey only works again on the same `SERVANAGO_HOST`.
