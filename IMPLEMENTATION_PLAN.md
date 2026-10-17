# M6+M7: Node.js and PHP-FPM providers (one pass)

Shared: site root stays admin-supplied (same validation as static, `/home` allowed), user `sg-<slug>`
per site, Caddy renders the whole config, helper does privileged work. `make check` gates every stage.

## Stage 1: schema + store model
`001_init.sql` in place: kind adds `node`/`php`, columns `upstream_port` shared for node port,
`start_command`, `install_command`, `build_command`, `fpm_version` (php), CHECK per kind.
`store.Site` fields, create/update/read. Tests in store.
**Status**: In Progress

## Stage 2: runtime detection
`internal/runtimes`: detect installed node (default binary) and php-fpm binaries (`/usr/sbin/php-fpm*`,
`/usr/bin/php-fpm*`, `/usr/local/bin/php-fpm*`); versions from names; shown on the dashboard card with the
install command. Runtimes are never installed. Cached 30s.
**Status**: Not Started

## Stage 3: helper — user + units for runtimes
Actions: `user-add {slug,root}` (system user sg-<slug>, chowns the root), `unit-install` gains kind fields
(Spec: Kind, Root, Port, StartCmd, FPMBin, FPMVersion):
- node template: sandboxed unit (NonRoot user, ProtectSystem=strict, ReadWritePaths=root, NoNewPrivileges),
  ExecStart=/bin/sh -c <start>
- php template: same sandbox + ExecStart=<fpm> -F --fpm-config /etc/servanago/fpm/<slug>.conf, plus the
  per-site pool file (listen /run/servanago/<slug>.sock 0660, listen.owner/group servanago, pm dynamic)
- `unit-remove {slug}`, `unit-start {slug}`, `unit-stop {slug}`
Real seam: php-fpm -t before reload/enable/start (node verify only by systemd-analyze). Fake seam tests.
**Status**: Not Started

## Stage 4: site form + caddy render + panel
Form kinds node (root, port, start + install/build strings) and php (root, version dropdown from detection).
`createSite`/`updateSite`: Mutate then helper (user-add, unit-install, start when enabled); delete: unit-remove
+ user-remove, best-effort. `toggleSite`: start/stop. php render = documented php_fastcgi expansion in JSON
(canonical redir, indexFiles rewrite, fastcgi reverse_proxy, dotfile 404, file_server); node renders like proxy
(127.0.0.1:port). Golden + in-process caddytests for node (via httptest upstream as its port) and php shape.
Probe: node probes like proxy; php rows show no upstream column (socket state comes with the panel).
**Status**: Not Started

## Stage 5: dashboard runtime card + docs + live DB conversion + gate
Runtime card on the dashboard (versions + install command). ROADMAP M6/M7 rows, README (new kinds),
CLAUDE.md. Live DB converted (stop, backup `*.pre-m6`, rebuild from 001, count checks), plan deleted.
**Status**: Not Started