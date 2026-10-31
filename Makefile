.PHONY: install test lint format backend-dev docker-up docker-down clean

install:
	cd backend && pip install -e ".[dev]"

test:
	./scripts/run_tests.sh

lint:
	./scripts/lint.sh

format:
	cd backend && ruff format app tests && ruff check --fix app tests

backend-dev:
	cd backend && uvicorn app.main:app --reload

docker-up:
	docker compose up -d postgres

docker-down:
	docker compose down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
