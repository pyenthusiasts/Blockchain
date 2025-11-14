.PHONY: help install install-dev test test-cov lint format clean docker-build docker-run docs examples

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := pip3
PYTEST := pytest
BLACK := black
FLAKE8 := flake8
PYLINT := pylint
MYPY := mypy

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package and dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

install-dev: ## Install package with development dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -e .
	$(PIP) install pytest pytest-cov pytest-mock black flake8 pylint mypy bandit safety pre-commit

test: ## Run tests
	$(PYTEST) tests/ -v

test-cov: ## Run tests with coverage
	$(PYTEST) tests/ -v --cov=blockchain_core --cov-report=html --cov-report=term --cov-report=xml

test-fast: ## Run tests excluding slow tests
	$(PYTEST) tests/ -v -m "not slow"

test-watch: ## Run tests in watch mode
	$(PYTEST) tests/ -v --looponfail

lint: ## Run all linters
	@echo "Running flake8..."
	$(FLAKE8) blockchain_core tests examples --max-line-length=120 --exclude=__pycache__,*.pyc
	@echo "Running pylint..."
	$(PYLINT) blockchain_core --max-line-length=120 --disable=C0103,R0913 || true
	@echo "Running mypy..."
	$(MYPY) blockchain_core --ignore-missing-imports --no-strict-optional || true

format: ## Format code with black
	$(BLACK) blockchain_core tests examples cli api config

format-check: ## Check code formatting
	$(BLACK) --check blockchain_core tests examples cli api config

security: ## Run security checks
	@echo "Running bandit..."
	bandit -r blockchain_core -f json -o bandit-report.json || true
	@echo "Running safety..."
	safety check || true

clean: ## Clean up generated files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.orig" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .pytest_cache/ .coverage htmlcov/ .mypy_cache/
	rm -f *.db *.blockchain blockchain_export.json bandit-report.json
	@echo "Cleanup complete!"

clean-all: clean ## Clean everything including venv
	rm -rf venv/ env/

build: ## Build distribution packages
	$(PYTHON) setup.py sdist bdist_wheel

docker-build: ## Build Docker image
	docker build -t blockchain:latest .

docker-run: ## Run Docker container
	docker run -it --rm blockchain:latest

docker-compose-up: ## Start services with docker-compose
	docker-compose up

docker-compose-down: ## Stop services with docker-compose
	docker-compose down

docker-compose-build: ## Build services with docker-compose
	docker-compose build

docs: ## Generate documentation
	@echo "Documentation is in docs/ directory"
	@echo "API docs: docs/API.md"
	@echo "Contributing: CONTRIBUTING.md"
	@echo "Changelog: CHANGELOG.md"

examples: ## Run example scripts
	@echo "Running basic usage example..."
	$(PYTHON) examples/basic_usage.py
	@echo "\nRunning advanced features example..."
	$(PYTHON) examples/advanced_features.py

example-basic: ## Run basic usage example
	$(PYTHON) examples/basic_usage.py

example-advanced: ## Run advanced features example
	$(PYTHON) examples/advanced_features.py

cli: ## Show CLI help
	$(PYTHON) -m cli.blockchain_cli --help

api: ## Run REST API server
	$(PYTHON) -m api.blockchain_api

api-dev: ## Run REST API server in development mode
	FLASK_ENV=development $(PYTHON) -m api.blockchain_api

benchmark: ## Run performance benchmarks
	$(PYTHON) -m tests.benchmarks

pre-commit: ## Install pre-commit hooks
	pre-commit install

pre-commit-run: ## Run pre-commit on all files
	pre-commit run --all-files

init: install-dev pre-commit ## Initialize development environment
	@echo "Development environment initialized!"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make examples' to run examples"

check: lint test ## Run linters and tests
	@echo "All checks passed!"

ci: clean lint test-cov security ## Run CI pipeline locally
	@echo "CI pipeline complete!"

dev-setup: ## Setup for development
	@echo "Setting up development environment..."
	$(PYTHON) -m venv venv
	@echo "Virtual environment created."
	@echo "Activate it with: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)"
	@echo "Then run: make install-dev"

requirements: ## Update requirements.txt
	$(PIP) freeze > requirements.txt

upgrade: ## Upgrade all dependencies
	$(PIP) list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 $(PIP) install -U

version: ## Show version information
	@echo "Python version:"
	@$(PYTHON) --version
	@echo "\nPackage version:"
	@$(PYTHON) -c "from blockchain_core import __version__; print(__version__)"

stats: ## Show project statistics
	@echo "=== Project Statistics ==="
	@echo "\nLines of code:"
	@find blockchain_core -name "*.py" | xargs wc -l | tail -1
	@echo "\nTest files:"
	@find tests -name "test_*.py" | wc -l
	@echo "\nTotal files:"
	@find blockchain_core tests examples cli api -name "*.py" | wc -l

todo: ## Show TODO items in code
	@grep -rn "TODO\|FIXME\|XXX" blockchain_core tests examples cli api || echo "No TODOs found!"

.PHONY: watch
watch: ## Watch for changes and run tests
	@echo "Watching for changes..."
	@while true; do \
		make test; \
		inotifywait -qre close_write blockchain_core tests; \
	done
