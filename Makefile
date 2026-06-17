.PHONY: local-up local-down local-logs run-orchestrator fmt check

COMPOSE_FILE := infrastructure/local-dev/docker-compose.yml

local-up:
	docker compose -f $(COMPOSE_FILE) up -d

local-down:
	docker compose -f $(COMPOSE_FILE) down

local-logs:
	docker compose -f $(COMPOSE_FILE) logs -f

run-orchestrator:
	cargo run -p orchestrator

fmt:
	cargo fmt --all

check:
	cargo check --workspace
