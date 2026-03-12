.PHONY: install hooks lint test compile up down logs topics workers replay migrate smoke metrics requirements

install:
	pip install -e .

hooks:
	python -m pip install pre-commit
	pre-commit install --install-hooks

lint:
	pre-commit run --all-files

# Regenerate requirements.txt from requirements.in (for deterministic Docker builds)
requirements:
	pip install pip-tools
	pip-compile requirements.in -o requirements.txt

test:
	python -m unittest discover -s tests

compile:
	python -m compileall src

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

topics:
	slop-bootstrap-topics

workers:
	@echo "Run these in separate terminals:"
	@echo "  slop-generator-service"
	@echo "  slop-notary-service"
	@echo "  slop-ledger-service"
	@echo "  slop-provenance-service"
	@echo "  slop-telemetry-service"

replay:
	slop-replay-dlq --topic story.signed --max-messages 50

migrate:
	python scripts/migrate_state_v2.py --db-path state.db

smoke:
	slop-smoke-kafka --bootstrap-topics --bootstrap-servers localhost:9094 --ledger-repo-path ./ledger --timeout-sec 180

metrics:
	slop-metrics --metrics-dir ./.metrics
