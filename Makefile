.PHONY: local-up local-down local-logs run-orchestrator run-paperclip run-codex-scheduler fmt check check-rust check-automation

COMPOSE_FILE := infrastructure/local-dev/docker-compose.yml

local-up:
	docker compose -f $(COMPOSE_FILE) up -d

local-down:
	docker compose -f $(COMPOSE_FILE) down

local-logs:
	docker compose -f $(COMPOSE_FILE) logs -f

run-orchestrator:
	cargo run -p orchestrator

run-paperclip:
	npx --registry https://registry.npmjs.org paperclipai run

run-codex-scheduler:
	python3 tools/codex_scheduler_bridge.py

fmt:
	cargo fmt --all

check: check-rust check-automation

check-rust:
	cargo check --workspace

check-automation:
	bash -n tools/*.sh paperclip/routines/*.sh
	python3 -m py_compile tools/*.py
	find paperclip -name '*.json' -print0 | xargs -0 -n1 python3 -m json.tool >/dev/null
	ALLOW_DIRTY_START=true DRY_RUN=true MAX_CODEX_RUNS=1 VERIFY_COMMAND=true tools/neuroplexis_lab_maintenance.sh
