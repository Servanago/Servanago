.PHONY: test lint e2e check build docker

test:
	go test -race ./...

lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	golangci-lint run

e2e: build
	@if [ -d e2e ]; then cd e2e && bun install --frozen-lockfile && bunx playwright test; else echo "no e2e tests yet"; fi

check: lint test e2e

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/caretakarr ./cmd/caretakarr

docker:
	docker build -t ghcr.io/caretakarr/caretakarr .
