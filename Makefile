.PHONY: install test compile up down logs topics workers replay migrate smoke metrics

install:
	pip install -e .

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
	slop-smoke-kafka --bootstrap-topics --ledger-repo-path ./ledger --timeout-sec 180

metrics:
	slop-metrics --metrics-dir ./.metrics
