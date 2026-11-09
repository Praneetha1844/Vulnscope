.PHONY: install lint format typecheck test check

install:
	pip install -e ".[dev]"

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy

test:
	pytest --cov=src --cov-report=term-missing

check: lint typecheck test
