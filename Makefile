.PHONY: install hooks lint test compile up down logs migrate metrics requirements

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
	pytest -v

compile:
	python -m compileall src

up:
	docker compose -f src/kafka/docker-compose.yml up --build -d

down:
	docker compose -f src/kafka/docker-compose.yml down

logs:
	docker compose -f src/kafka/docker-compose.yml logs -f

migrate:
	python scripts/migrate_state_v2.py --db-path state.db

metrics:
	slop-metrics --metrics-dir ./.metrics
