# M3: Native packaging

## Stage 1: DATA_DIR default
**Goal**: `DATA_DIR` defaults to `/var/lib/servanago` instead of the container path `/data`.
**Success Criteria**: `config.Load` with no `DATA_DIR` yields `/var/lib/servanago`; ROADMAP known-gap line removed.
**Tests**: `internal/config/config_test.go` — unset `DATA_DIR` defaults to `/var/lib/servanago`.
**Status**: Complete

## Stage 2: systemd unit + env template
**Goal**: `packaging/servanago.service` (User/Group servanago, `EnvironmentFile=-/etc/servanago/servanago.env`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, never `ProtectHome=yes`, Restart=on-failure) and `packaging/servanago.env` template listing every env var.
**Success Criteria**: unit matches the M2 rule (no ProtectHome=yes), runs unprivileged with only bind capability.
**Tests**: Go test reads `packaging/servanago.service` and asserts the contract lines absent/present.
**Status**: Not Started

## Stage 3: .deb package
**Goal**: staging tree + `make deb` building `bin/servanago_*.deb` with `dpkg-deb`: binary at `/usr/bin/servanago`, unit at correct systemd path, conffile env, postinst creates user/dirs and enables the unit, prerm stops it.
**Success Criteria**: `make deb` produces a deb whose file list and scripts are correct; unit enables with the right paths.
**Tests**: Go test builds the deb (skipped when `dpkg-deb` is absent) and inspects `dpkg-deb --info`/`-c` output.
**Status**: Not Started

## Stage 4: install script
**Goal**: `packaging/install.sh` — root-only, builds the deb (reusing stage 3) and installs it with apt/dpkg; no duplicated host-setup logic.
**Success Criteria**: script refuses to run non-root, installs the deb.
**Tests**: `bash -n` syntax check in a Go test.
**Status**: Not Started

## Stage 5: docs
**Goal**: README install section (deb + env file), `.env.example` updated, ROADMAP M3 → Done, plan deleted.
**Status**: Not Started