.PHONY: install lint test compile migrate lock

install:
	uv sync --extra dev

lint:
	uv run ruff check .
	uv run ruff format --check .

lock:
	uv lock

test:
	uv run pytest -v

compile:
	uv run python -m compileall src

migrate:
	uv run python scripts/migrate_state_v2.py --db-path state.db
