.SILENT:

GO ?= go
GOLANGCI_LINT ?= golangci-lint

PKG := ./...
BIN := bin/khrazhevnik
COVER_OUT := coverage/coverage.out
WEB_ASSETS := internal/core/web/assets

# Образ: реестр/репо и тег по умолчанию. CI передаёт TAG=версия.
# Нативная платформа по умолчанию (быстро, без QEMU); для релиза:
#   make image PLATFORMS=linux/amd64,linux/arm64
# (кросс-сборка arm64 на x86 требует qemu-user-static + binfmt_misc).
IMAGE     ?= ghcr.io/alexrus1234/khrazhevnik
TAG       ?= dev
PLATFORMS ?= linux/amd64

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

# image — сборка OCI-образа из deploy/Containerfile в scratch.
# --manifest создаёт manifest list (даже для одной платформы), что
# позволяет `podman run` выбирать нативную запись и `podman push`
# пушить multi-арх. --build-arg VERSION инжектит тег в main.Version.
.PHONY: image
image:
	podman build --platform='$(PLATFORMS)' --manifest '$(IMAGE):$(TAG)' \
	    --build-arg VERSION='$(TAG)' -f deploy/Containerfile .

.PHONY: clean
clean:
	$(GO) clean
	rm -rf bin coverage dist
	rm -rf $(WEB_ASSETS)
	mkdir -p $(WEB_ASSETS)
	printf '<!doctype html>\n<html lang="ru"><head><meta charset="utf-8"><title>khrazhevnik</title></head><body><p>Web UI не собран.</p></body></html>\n' > $(WEB_ASSETS)/index.html

# smoke — дымовой тест живого контейнера (нужен podman + python3).
# Образ должен быть собран: `make image && make smoke`.
.PHONY: smoke
smoke:
	test/smoke/smoke.sh
