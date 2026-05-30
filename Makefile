.DEFAULT_GOAL := build

APP := gibcert
CMD := ./cmd/$(APP)
PREFIX ?= /usr/local
DESTDIR ?=
BASH_COMPLETION_DIR ?= $(PREFIX)/share/bash-completion/completions
ZSH_COMPLETION_DIR  ?= $(PREFIX)/share/zsh/site-functions
FISH_COMPLETION_DIR ?= $(PREFIX)/share/fish/vendor_completions.d

GO ?= go
GOFLAGS ?=
GORELEASER_VERSION ?= latest
GORELEASER ?= $(GO) run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)
MODULE := $(shell $(GO) list -m)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILT_BY ?= make
LDFLAGS ?= -s -w -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/buildinfo.Date=$(DATE) -X $(MODULE)/internal/buildinfo.BuiltBy=$(BUILT_BY)
BUILD_FLAGS ?= -trimpath -ldflags "$(LDFLAGS)"

CONFIG ?=
STATE_DIR ?= .state
ARGS ?= help
CONTAINER ?= podman
PEBBLE_MODE ?= container
PEBBLE_IMAGE ?= ghcr.io/letsencrypt/pebble:latest
PEBBLE_MODULE ?= github.com/letsencrypt/pebble/v2
PEBBLE_CMD ?= $(PEBBLE_MODULE)/cmd/pebble@latest
PEBBLE_EAB_NAME ?= gibcert-pebble-eab
PEBBLE_EAB_URL ?= https://127.0.0.1:14000/dir
PEBBLE_EAB_CONFIG ?= $(CURDIR)/internal/acmeclient/testdata/pebble-eab-config.json
PEBBLE_EAB_PID ?= $(STATE_DIR)/pebble-eab.pid
PEBBLE_EAB_LOG ?= $(STATE_DIR)/pebble-eab.log

.PHONY: help all build run install uninstall completions test test-race test-pebble-eab pebble-eab-up pebble-down lint vet fmt fmt-check tidy clean check config-check version snapshot release

help:
	@printf '%s\n' \
		'Targets:' \
		'  make build          Build ./gibcert' \
		'  make version        Print CLI version metadata' \
		'  make run            Run the CLI (override ARGS=...)' \
		'  make install        Install binary and shell completions' \
		'  make uninstall      Remove installed binary and completions' \
		'  make completions    Regenerate contrib/completions/ from the binary' \
		'  make test           Run unit tests' \
		'  make test-race      Run tests with the race detector' \
		'  make test-pebble-eab Start Pebble with EAB required and run EAB integration tests' \
		'  make lint           Run formatting check and go vet' \
		'  make fmt            Format Go files' \
		'  make tidy           Tidy go.mod/go.sum' \
		'  make snapshot       Build a local GoReleaser snapshot' \
		'  make release        Publish a GoReleaser release' \
		'  make clean          Remove build output' \
		'  make config-check   Validate CONFIG with an isolated state dir' \
		'' \
		'Examples:' \
		'  make run ARGS="--config testdata/example.scfg check"' \
		'  make config-check CONFIG=testdata/example.scfg' \
		'  make test-pebble-eab CONTAINER=docker' \
		'  make test-pebble-eab PEBBLE_MODE=go-run' \
		'  make install PREFIX=/usr/local'

all: lint test build

build:
	$(GO) build $(GOFLAGS) $(BUILD_FLAGS) -o $(APP) $(CMD)

version: build
	./$(APP) version

run:
	$(GO) run $(GOFLAGS) $(CMD) $(ARGS)

install: build completions
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(APP) $(DESTDIR)$(PREFIX)/bin/$(APP)
	install -d $(DESTDIR)$(BASH_COMPLETION_DIR)
	install -m 0644 contrib/completions/$(APP).bash $(DESTDIR)$(BASH_COMPLETION_DIR)/$(APP)
	install -d $(DESTDIR)$(ZSH_COMPLETION_DIR)
	install -m 0644 contrib/completions/_$(APP) $(DESTDIR)$(ZSH_COMPLETION_DIR)/_$(APP)
	install -d $(DESTDIR)$(FISH_COMPLETION_DIR)
	install -m 0644 contrib/completions/$(APP).fish $(DESTDIR)$(FISH_COMPLETION_DIR)/$(APP).fish

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(APP)
	rm -f $(DESTDIR)$(BASH_COMPLETION_DIR)/$(APP)
	rm -f $(DESTDIR)$(ZSH_COMPLETION_DIR)/_$(APP)
	rm -f $(DESTDIR)$(FISH_COMPLETION_DIR)/$(APP).fish

completions: build
	./$(APP) completion bash > contrib/completions/$(APP).bash
	./$(APP) completion zsh  > contrib/completions/_$(APP)
	./$(APP) completion fish > contrib/completions/$(APP).fish

test:
	$(GO) test $(GOFLAGS) ./...

test-race:
	$(GO) test $(GOFLAGS) -race ./...

pebble-eab-up:
	@mkdir -p "$(STATE_DIR)"
	@if [ "$(PEBBLE_MODE)" = "container" ]; then \
		$(CONTAINER) rm -f $(PEBBLE_EAB_NAME) >/dev/null 2>&1 || true; \
		$(CONTAINER) run -d --name $(PEBBLE_EAB_NAME) \
			-p 127.0.0.1:14000:14000 \
			-p 127.0.0.1:15000:15000 \
			-e PEBBLE_VA_NOSLEEP=1 \
			--mount type=bind,src=$(PEBBLE_EAB_CONFIG),target=/test/pebble-eab-config.json,ro \
			$(PEBBLE_IMAGE) -config /test/pebble-eab-config.json; \
	elif [ "$(PEBBLE_MODE)" = "go-run" ]; then \
		if [ -f "$(PEBBLE_EAB_PID)" ] && kill -0 "$$(cat "$(PEBBLE_EAB_PID)")" >/dev/null 2>&1; then \
			kill "$$(cat "$(PEBBLE_EAB_PID)")" >/dev/null 2>&1 || true; \
		fi; \
		rm -f "$(PEBBLE_EAB_PID)" "$(PEBBLE_EAB_LOG)"; \
		pebble_dir="$$($(GO) list -m -f '{{.Dir}}' $(PEBBLE_MODULE)@latest)"; \
		(cd "$$pebble_dir" && exec env PEBBLE_VA_NOSLEEP=1 $(GO) run $(PEBBLE_CMD) -config "$(PEBBLE_EAB_CONFIG)") >"$(PEBBLE_EAB_LOG)" 2>&1 & \
		echo $$! >"$(PEBBLE_EAB_PID)"; \
	else \
		echo 'unsupported PEBBLE_MODE="$(PEBBLE_MODE)" (want container or go-run)'; \
		exit 2; \
	fi
	@for i in $$(seq 1 50); do \
		if curl -kfsS $(PEBBLE_EAB_URL) >/dev/null 2>&1; then \
			echo 'Pebble EAB is ready at $(PEBBLE_EAB_URL) ($(PEBBLE_MODE))'; \
			exit 0; \
		fi; \
		sleep 0.2; \
	done; \
	if [ "$(PEBBLE_MODE)" = "container" ]; then \
		$(CONTAINER) logs $(PEBBLE_EAB_NAME); \
	else \
		cat "$(PEBBLE_EAB_LOG)"; \
	fi; \
	exit 1

pebble-down:
	@$(CONTAINER) rm -f $(PEBBLE_EAB_NAME) >/dev/null 2>&1 || true
	@if [ -f "$(PEBBLE_EAB_PID)" ]; then \
		kill "$$(cat "$(PEBBLE_EAB_PID)")" >/dev/null 2>&1 || true; \
		rm -f "$(PEBBLE_EAB_PID)"; \
	fi
	@rm -f "$(PEBBLE_EAB_LOG)"

test-pebble-eab:
	@set -e; \
	$(MAKE) pebble-eab-up; \
	trap '$(MAKE) pebble-down' EXIT; \
	GIBCERT_PEBBLE_EAB_DIRECTORY_URL=$(PEBBLE_EAB_URL) \
		$(GO) test $(GOFLAGS) ./internal/acmeclient -run 'TestPebbleEAB' -count=1 -v

lint: fmt-check vet

vet:
	$(GO) vet $(GOFLAGS) ./...

fmt:
	$(GO) fmt $(GOFLAGS) ./...

fmt-check:
	@test -z "$$($(GO)fmt -l .)" || { \
		echo 'Go files need formatting:'; \
		$(GO)fmt -l .; \
		exit 1; \
	}

tidy:
	$(GO) mod tidy

snapshot:
	$(GORELEASER) release --snapshot --clean

release:
	$(GORELEASER) release --clean

clean:
	rm -rf $(APP) dist coverage.out

check: all

config-check:
	@test -n "$(CONFIG)" || { \
		echo 'Set CONFIG=path/to/gibcert.scfg'; \
		exit 2; \
	}
	$(GO) run $(GOFLAGS) $(CMD) --config $(CONFIG) --state-dir $(STATE_DIR) check
