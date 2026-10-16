.PHONY: test lint e2e check build docker

# Scoped to cmd/ and internal/ (not ./...): a local ./data volume owned by the container user is unreadable to Go tooling.
PKGS = ./cmd/... ./internal/...

test:
	go test -race $(PKGS)

lint:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	golangci-lint run $(PKGS)

e2e: build
	@if [ -d e2e ]; then cd e2e && bun install --frozen-lockfile && bunx playwright test; else echo "no e2e tests yet"; fi

check: lint test e2e

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/servanago ./cmd/servanago

docker:
	docker build -t ghcr.io/servanago/servanago .
