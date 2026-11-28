.DEFAULT_GOAL := help

VERSION ?= 0.1.0
GO_IMAGE ?= golang:1.22-alpine
PY_IMAGE ?= python:3.12-slim
NODE_IMAGE ?= node:22-alpine
SHELLCHECK_IMAGE ?= koalaman/shellcheck-alpine:v0.10.0

COMPOSE_FILE := $(CURDIR)/deploy/docker-compose.yml
ENV_FILE := $(CURDIR)/deploy/.env
AGENT_DIR := $(CURDIR)/agent
RELAY_DIR := $(CURDIR)/relay
SERVER_DIR := $(CURDIR)/server
WEB_DIR := $(CURDIR)/web
DIST_AGENT_DIR := $(CURDIR)/dist/agent
DIST_RELAY_DIR := $(CURDIR)/dist/relay

DOCKER_USER := -u $$(id -u):$$(id -g)

.PHONY: help build-agent lint-agent test-agent \
        build-relay lint-relay test-relay \
        lint-server test-server lint-shell \
        lint-web test-web build-web \
        test bundle-lynis validate-compose \
        up down logs clean

help: ## Muestra los comandos disponibles de HostGrid
	@printf "HostGrid v%s — Comandos disponibles:\n\n" "$(VERSION)"
	@grep -E '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build-agent: ## Compila hostgrid-agent estático (CGO_ENABLED=0) para amd64, arm64 y 386
	@mkdir -p "$(DIST_AGENT_DIR)"
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/go-build \
		-e GOMODCACHE=/tmp/go-mod \
		-e CGO_ENABLED=0 \
		-v "$(CURDIR):/workspace" \
		-w /workspace/agent \
		"$(GO_IMAGE)" sh -c '\
			set -eu; \
			for arch in amd64 arm64 386; do \
				GOOS=linux GOARCH="$$arch" go build -trimpath \
					-ldflags="-s -w -X main.version=$(VERSION)" \
					-o "/workspace/dist/agent/hostgrid-agent-linux-$${arch}" \
					./cmd/hostgrid-agent; \
			done; \
			cd /workspace/dist/agent && sha256sum hostgrid-agent-linux-* > SHA256SUMS'

lint-agent: ## Ejecuta gofmt check y go vet sobre el agente Go
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/go-build \
		-e GOMODCACHE=/tmp/go-mod \
		-v "$(AGENT_DIR):/src:ro" \
		-w /src \
		"$(GO_IMAGE)" sh -c '\
			set -eu; \
			unformatted=$$(gofmt -l .); \
			if [ -n "$$unformatted" ]; then echo "Archivos sin gofmt:"; echo "$$unformatted"; exit 1; fi; \
			go vet ./...'

test-agent: ## Ejecuta pruebas unitarias del agente Go en contenedor efímero
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/go-build \
		-e GOMODCACHE=/tmp/go-mod \
		-e CGO_ENABLED=0 \
		-v "$(AGENT_DIR):/src:ro" \
		-w /src \
		"$(GO_IMAGE)" go test -v ./...

build-relay: ## Compila hostgrid-relay estático (CGO_ENABLED=0) para amd64 y arm64
	@mkdir -p "$(DIST_RELAY_DIR)"
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/go-build \
		-e GOMODCACHE=/tmp/go-mod \
		-e CGO_ENABLED=0 \
		-v "$(CURDIR):/workspace" \
		-w /workspace/relay \
		"$(GO_IMAGE)" sh -c '\
			set -eu; \
			for arch in amd64 arm64; do \
				GOOS=linux GOARCH="$$arch" go build -trimpath \
					-ldflags="-s -w -X main.version=$(VERSION)" \
					-o "/workspace/dist/relay/hostgrid-relay-linux-$${arch}" \
					./cmd/hostgrid-relay; \
			done; \
			cd /workspace/dist/relay && sha256sum hostgrid-relay-linux-* > SHA256SUMS'

lint-relay: ## Ejecuta gofmt check y go vet sobre el nodo Relay DMZ
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/go-build \
		-e GOMODCACHE=/tmp/go-mod \
		-v "$(RELAY_DIR):/src:ro" \
		-w /src \
		"$(GO_IMAGE)" sh -c '\
			set -eu; \
			unformatted=$$(gofmt -l .); \
			if [ -n "$$unformatted" ]; then echo "Archivos sin gofmt:"; echo "$$unformatted"; exit 1; fi; \
			go vet ./...'

test-relay: ## Ejecuta pruebas unitarias del nodo Relay DMZ en contenedor efímero
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/go-build \
		-e GOMODCACHE=/tmp/go-mod \
		-e CGO_ENABLED=0 \
		-v "$(RELAY_DIR):/src:ro" \
		-w /src \
		"$(GO_IMAGE)" go test -v ./...

lint-server: ## Ejecuta ruff y mypy --strict sobre el backend Python
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e PIP_CACHE_DIR=/tmp/pip-cache \
		-v "$(SERVER_DIR):/src:ro" \
		-w /src \
		"$(PY_IMAGE)" sh -c '\
			set -eu; \
			mkdir -p /tmp/build_pkg && cp /src/pyproject.toml /tmp/build_pkg/ && cp -r /src/app /tmp/build_pkg/; \
			python3 -m venv /tmp/venv; \
			/tmp/venv/bin/pip install --quiet "/tmp/build_pkg[dev]"; \
			/tmp/venv/bin/pip uninstall -y --quiet hostgrid-server; \
			PYTHONPATH=/src /tmp/venv/bin/ruff check --cache-dir=/tmp/ruff-cache app tests; \
			PYTHONPATH=/src /tmp/venv/bin/mypy --strict --cache-dir=/tmp/mypy app tests'

test-server: ## Ejecuta pytest con cobertura >=95% en contenedor Python efímero
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e PIP_CACHE_DIR=/tmp/pip-cache \
		-e COVERAGE_FILE=/tmp/.coverage \
		-v "$(SERVER_DIR):/src:ro" \
		-w /src \
		"$(PY_IMAGE)" sh -c '\
			set -eu; \
			mkdir -p /tmp/build_pkg && cp /src/pyproject.toml /tmp/build_pkg/ && cp -r /src/app /tmp/build_pkg/; \
			python3 -m venv /tmp/venv; \
			/tmp/venv/bin/pip install --quiet "/tmp/build_pkg[dev]"; \
			/tmp/venv/bin/pip uninstall -y --quiet hostgrid-server; \
			PYTHONPATH=/src /tmp/venv/bin/pytest -o cache_dir=/tmp/pytest-cache'

lint-shell: ## Valida scripts POSIX/Bash con shellcheck (cuando existan)
	@scripts=""; \
	for f in "$(CURDIR)/agentless/collect_posix.sh" "$(CURDIR)/tools-packaging/build_lynis_bundle.sh" "$(CURDIR)/server/docker-entrypoint.sh" "$(CURDIR)/web/docker-entrypoint.sh"; do \
		if [ -f "$$f" ]; then scripts="$$scripts /workspace/$${f#$(CURDIR)/}"; fi; \
	done; \
	if [ -z "$$scripts" ]; then \
		echo "Sin scripts shell implementados aún (esperado en Fase 0)."; \
	else \
		docker run --rm $(DOCKER_USER) -v "$(CURDIR):/workspace:ro" "$(SHELLCHECK_IMAGE)" shellcheck -s sh $$scripts; \
	fi

lint-web: ## Ejecuta typecheck y eslint del frontend en contenedor Node efímero
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e npm_config_cache=/tmp/npm-cache \
		-v "$(WEB_DIR):/src" \
		-w /src \
		"$(NODE_IMAGE)" sh -c 'npm ci --ignore-scripts && npm run typecheck && npm run lint'

test-web: ## Ejecuta pruebas unitarias del frontend con Vitest en contenedor Node efímero
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e npm_config_cache=/tmp/npm-cache \
		-v "$(WEB_DIR):/src" \
		-w /src \
		"$(NODE_IMAGE)" sh -c 'npm ci --ignore-scripts && npm test'

build-web: ## Compila bundle de producción del frontend en contenedor Node efímero
	docker run --rm $(DOCKER_USER) \
		-e HOME=/tmp \
		-e npm_config_cache=/tmp/npm-cache \
		-v "$(WEB_DIR):/src" \
		-w /src \
		"$(NODE_IMAGE)" sh -c 'npm ci --ignore-scripts && npm run build'

test: test-server test-agent test-relay test-web ## Ejecuta todas las suites de pruebas (server, agent, relay, web)

bundle-lynis: ## Empaqueta y firma el bundle portable de Lynis (Fase 1)
	@test -x "$(CURDIR)/tools-packaging/build_lynis_bundle.sh" || { \
		echo "tools-packaging/build_lynis_bundle.sh aún no está implementado (Fase 1)."; exit 1; \
	}
	"$(CURDIR)/tools-packaging/build_lynis_bundle.sh"

validate-compose: ## Valida la sintaxis de deploy/docker-compose.yml (incluyendo perfil relay) sin exponer secretos reales
	POSTGRES_PASSWORD=ephemeral_compose_validation_only \
	HOSTGRID_JWT_SECRET=ephemeral_compose_validation_secret_only \
	docker compose --profile relay -f "$(COMPOSE_FILE)" config --quiet
	@echo "docker-compose.yml válido."

up: ## Levanta el stack de Control Plane + DB + Frontend con Docker Compose
	@test -f "$(ENV_FILE)" || { echo "Falta $(ENV_FILE). Copie deploy/.env.example y configure secretos."; exit 1; }
	docker compose --env-file "$(ENV_FILE)" -f "$(COMPOSE_FILE)" up -d --build

down: ## Detiene los servicios de HostGrid
	@if [ -f "$(ENV_FILE)" ]; then \
		docker compose --env-file "$(ENV_FILE)" -f "$(COMPOSE_FILE)" down; \
	else \
		POSTGRES_PASSWORD=unused HOSTGRID_JWT_SECRET=unused_placeholder_secret_for_down_only \
			docker compose -f "$(COMPOSE_FILE)" down; \
	fi

logs: ## Muestra logs en vivo de los servicios de HostGrid
	@if [ -f "$(ENV_FILE)" ]; then \
		docker compose --env-file "$(ENV_FILE)" -f "$(COMPOSE_FILE)" logs -f --tail=100; \
	else \
		POSTGRES_PASSWORD=unused HOSTGRID_JWT_SECRET=unused_placeholder_secret_for_logs_only \
			docker compose -f "$(COMPOSE_FILE)" logs -f --tail=100; \
	fi

clean: ## Limpia artefactos compilados en dist/
	rm -rf "$(CURDIR)/dist"
