# Development

```sh
make test    # go test -race ./cmd/... ./internal/...
make lint    # gofmt + golangci-lint
make e2e     # Playwright against the built binary (bun + chromium)
make check   # all of the above
make build   # static binary in bin/
```

## Real PHP compile

About nine minutes with 8 jobs. It downloads php.net and every library, so it is not part of `make check`.

```sh
SMOKE_ROOT=/tmp/phpsmoke SMOKE_VERSION=8.4.27 go test -tags smoke -run SmokeRealBuild -timeout 3h -v ./internal/phpbuild
```

It needs the build tools listed in [PHP built from source](php.md), and builds into the empty directory you name. It does not use systemd or the helper.

## Other docs

- [RELEASING.md](RELEASING.md): how to cut a release.
- [ROADMAP.md](ROADMAP.md): the roadmap and the decisions behind it.
- [DESIGN.md](DESIGN.md) and [REQUIREMENTS.md](REQUIREMENTS.md): the inherited baseline's design notes and requirements. Both predate the roadmap and are being reworked milestone by milestone.
- [brand/README.md](brand/README.md): brand asset provenance.
