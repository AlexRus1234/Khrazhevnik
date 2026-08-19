.SILENT:

GO ?= go
GOLANGCI_LINT ?= golangci-lint

PKG := ./...
BIN := bin/khrazhevnik
COVER_OUT := coverage/coverage.out
WEB_ASSETS := internal/core/web/assets

.PHONY: all
all: lint test build

.PHONY: lint
lint:
	"$(GOLANGCI_LINT)" run ./...

.PHONY: vet
vet:
	"$(GO)" vet ./...

.PHONY: fmt
fmt:
	"$(GOLANGCI_LINT)" run --fix ./...

.PHONY: test
test:
	"$(GO)" test $(PKG)

.PHONY: test-race
test-race:
	"$(GO)" test -race $(PKG)

.PHONY: test-integration
test-integration:
	"$(GO)" test -race -tags integration ./test/integration/...

.PHONY: cover
cover:
	"$(GO)" test -coverprofile="$(COVER_OUT)" $(PKG)
	"$(GO)" tool cover -func="$(COVER_OUT)" | tail -n 1

.PHONY: build
build:
	"$(GO)" build -o "$(BIN)" ./cmd/khrazhevnik

.PHONY: clean
clean:
	$(GO) clean
	rm -rf bin coverage dist
	rm -rf $(WEB_ASSETS)
	mkdir -p $(WEB_ASSETS)
	printf '<!doctype html>\n<html lang="ru"><head><meta charset="utf-8"><title>khrazhevnik</title></head><body><p>Web UI не собран.</p></body></html>\n' > $(WEB_ASSETS)/index.html
