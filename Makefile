.PHONY: menu help on off deploy local-up local-down local-status local-logs run-orchestrator run-paperclip run-codex-scheduler run-webui fmt check check-rust check-webui check-automation check-opentofu check-workflows check-supply-chain

COMPOSE_FILE := infrastructure/local-dev/docker-compose.yml
TOFU ?= tofu

menu:
	@printf "\nAthernex lab menu\n"
	@printf "  1) Turn on local staging services\n"
	@printf "  2) Turn off local staging services\n"
	@printf "  3) Show local service status\n"
	@printf "  4) Follow local service logs\n"
	@printf "  5) Validate and deploy/push\n"
	@printf "  6) Run full validation only\n"
	@printf "  q) Quit\n\n"
	@printf "Select an option: "; \
	read choice; \
	case "$$choice" in \
		1) $(MAKE) on ;; \
		2) $(MAKE) off ;; \
		3) $(MAKE) local-status ;; \
		4) $(MAKE) local-logs ;; \
		5) $(MAKE) deploy ;; \
		6) $(MAKE) check ;; \
		q|Q) exit 0 ;; \
		*) echo "Unknown option: $$choice"; exit 2 ;; \
	esac

help:
	@printf "Athernex lab targets:\n"
	@printf "  make menu          Interactive operations menu\n"
	@printf "  make on            Turn on local Docker staging services\n"
	@printf "  make off           Turn off local Docker staging services\n"
	@printf "  make status        Show local Docker staging service status\n"
	@printf "  make local-logs    Follow local Docker staging service logs\n"
	@printf "  make check         Run validation suite\n"
	@printf "  make deploy        Run validation, then guarded dual push\n"

on: local-up

off: local-down

status: local-status

deploy: check
	tools/push_downstream.sh

local-up:
	docker compose -f $(COMPOSE_FILE) up -d

local-down:
	docker compose -f $(COMPOSE_FILE) down

local-status:
	docker compose -f $(COMPOSE_FILE) ps

local-logs:
	docker compose -f $(COMPOSE_FILE) logs -f

run-orchestrator:
	cargo run -p orchestrator

run-paperclip:
	npx --registry https://registry.npmjs.org paperclipai run

run-codex-scheduler:
	python3 tools/codex_scheduler_bridge.py

run-webui:
	npm --prefix webui run dev

fmt:
	cargo fmt --all

check: check-rust check-webui check-automation check-workflows check-supply-chain check-opentofu

check-rust:
	cargo check --workspace
	cargo test --workspace

check-webui:
	npm --prefix webui run build

check-automation:
	bash -n tools/*.sh paperclip/routines/*.sh
	python3 -m py_compile tools/*.py
	find paperclip -name '*.json' -print0 | xargs -0 -n1 python3 -m json.tool >/dev/null
	REPO_ROOT=$(CURDIR) ALLOW_DIRTY_START=true DRY_RUN=true MAX_CODEX_RUNS=1 VERIFY_COMMAND=true tools/neuroplexis_lab_maintenance.sh

check-workflows:
	python3 tools/validate_ci_workflow.py

check-supply-chain:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "cargo-audit not found; skipping Rust dependency audit"; \
	fi
	@if command -v cargo-cyclonedx >/dev/null 2>&1; then \
		tmp_dir=$$(mktemp -d); \
		cargo cyclonedx --format json --override-filename rust-sbom; \
		mv core-engines/orchestrator/rust-sbom.json "$$tmp_dir/rust-sbom.cdx.json"; \
		test -s "$$tmp_dir/rust-sbom.cdx.json"; \
		rm -rf "$$tmp_dir"; \
	else \
		echo "cargo-cyclonedx not found; skipping Rust SBOM generation"; \
	fi

check-opentofu:
	@if command -v $(TOFU) >/dev/null 2>&1; then \
		$(TOFU) -chdir=infrastructure/opentofu/kubernetes-scheduler-contract fmt -check -recursive; \
		$(TOFU) -chdir=infrastructure/opentofu/kubernetes-scheduler-contract init -backend=false; \
		$(TOFU) -chdir=infrastructure/opentofu/kubernetes-scheduler-contract validate; \
		$(TOFU) -chdir=infrastructure/opentofu/kubernetes-scheduler-contract test; \
	else \
		echo "OpenTofu not found; skipping check-opentofu"; \
	fi
