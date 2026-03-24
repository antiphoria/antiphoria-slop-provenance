.PHONY: install lint test compile migrate metrics requirements

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

# Regenerate requirements.txt from requirements.in (for deterministic Docker builds)
requirements:
	pip install pip-tools
	pip-compile requirements.in -o requirements.txt

test:
	pytest -v

compile:
	python -m compileall src

migrate:
	python scripts/migrate_state_v2.py --db-path state.db

metrics:
	slop-metrics --metrics-dir ./.metrics
