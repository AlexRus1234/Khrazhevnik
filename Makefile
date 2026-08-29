.SILENT:

GO ?= go
GOLANGCI_LINT ?= golangci-lint
NPM ?= npm

PKG := ./...
BIN := bin/khrazhevnik
COVER_OUT := coverage/coverage.out
COVER_INT_OUT := coverage/coverage-integration.out
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

# web-stub — заглушка index.html в $(WEB_ASSETS), чтобы //go:embed
# (internal/core/web/spa.go) компилировался без собранного фронтенда.
# Идемпотентна: не трогает существующий index.html (в т.ч. собранный
# web-build). Зависимость lint/vet/fmt/test/build — гарантия, что на
# свежем чекауте Go-команды видят ассеты (по образцу lentovodec, где
# без make clean/web-build go build падает на //go:embed).
.PHONY: web-stub
web-stub:
	@mkdir -p $(WEB_ASSETS) && { test -f $(WEB_ASSETS)/index.html || printf '<!doctype html>\n<html lang="ru"><head><meta charset="utf-8"><title>khrazhevnik</title></head><body><p>Web UI не собран. См. <code>make web-build</code>.</p></body></html>\n' > $(WEB_ASSETS)/index.html; }

.PHONY: lint
lint: web-stub
	"$(GOLANGCI_LINT)" run ./...

.PHONY: vet
vet: web-stub
	"$(GO)" vet ./...

.PHONY: fmt
fmt: web-stub
	"$(GOLANGCI_LINT)" run --fix ./...

.PHONY: test
test: web-stub
	"$(GO)" test $(PKG)

.PHONY: test-race
test-race: web-stub
	"$(GO)" test -race $(PKG)

.PHONY: test-integration
test-integration: web-stub
	"$(GO)" test -race -tags integration ./test/integration/...

# test-integration-cover — интеграционный профиль с инструментированием
# ВСЕХ пакетов (-coverpkg=./...): вклад integration-suite в покрытие.
# Объединение с unit-профилем — шаг Coverage report в CI (конкатенация
# с дедупликацией строк, см. docs/TESTING.md §Подсчёт покрытия).
.PHONY: test-integration-cover
test-integration-cover: web-stub
	@mkdir -p coverage
	"$(GO)" test -race -tags integration -covermode=atomic -coverpkg=./... -coverprofile="$(COVER_INT_OUT)" ./test/integration/...
	"$(GO)" tool cover -func="$(COVER_INT_OUT)" | tail -n 1

.PHONY: cover
cover: web-stub
	"$(GO)" test -coverprofile="$(COVER_OUT)" $(PKG)
	"$(GO)" tool cover -func="$(COVER_OUT)" | tail -n 1

.PHONY: build
build: web-stub
	"$(GO)" build -o "$(BIN)" ./cmd/khrazhevnik

# web-build — сборка реального SPA в $(WEB_ASSETS) (vue-tsc + vite build).
# emptyOutDir стирает папку; последующий build подхватит свежий бандл.
.PHONY: web-build
web-build:
	cd web && "$(NPM)" ci && "$(NPM)" run build

# web-dev — vite dev-сервер (прокси /api→:30202, /repo→:29202).
.PHONY: web-dev
web-dev:
	cd web && "$(NPM)" run dev

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
	@$(GO) clean; rm -rf bin coverage dist; rm -rf $(WEB_ASSETS); mkdir -p $(WEB_ASSETS); printf '<!doctype html>\n<html lang="ru"><head><meta charset="utf-8"><title>khrazhevnik</title></head><body><p>Web UI не собран. См. <code>make web-build</code>.</p></body></html>\n' > $(WEB_ASSETS)/index.html

# smoke — дымовой тест живого контейнера (нужен podman + python3).
# Образ должен быть собран: `make image && make smoke`.
.PHONY: smoke
smoke:
	test/smoke/smoke.sh
