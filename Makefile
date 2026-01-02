.PHONY: help install test lint format clean docker-build deploy

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies and setup development environment
	poetry install
	poetry run pre-commit install

install-libs: ## Install shared libraries in editable mode
	cd libs/python/ladon-common && poetry install
	cd libs/python/ladon-models && poetry install
	cd libs/python/ladon-clients && poetry install

test: ## Run all tests
	poetry run pytest -v --cov --cov-report=term-missing

test-unit: ## Run unit tests only
	poetry run pytest -v -m "not integration" --cov

test-integration: ## Run integration tests only
	poetry run pytest -v -m "integration"

test-service: ## Run tests for a specific service (usage: make test-service SERVICE=detection)
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE variable is required. Usage: make test-service SERVICE=detection"; \
		exit 1; \
	fi
	cd services/$(SERVICE) && poetry run pytest -v

lint: ## Run linters (ruff and mypy)
	poetry run ruff check .
	poetry run mypy .

format: ## Format code with black
	poetry run black .
	poetry run ruff check --fix .

clean: ## Clean build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/

docker-build-service: ## Build Docker image for a service (usage: make docker-build-service SERVICE=detection)
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE variable is required. Usage: make docker-build-service SERVICE=detection"; \
		exit 1; \
	fi
	docker build -t ladon-$(SERVICE):latest services/$(SERVICE)

docker-build-all: ## Build Docker images for all services
	@for service in services/*; do \
		if [ -d "$$service" ] && [ -f "$$service/Dockerfile" ]; then \
			service_name=$$(basename $$service); \
			echo "Building $$service_name..."; \
			docker build -t ladon-$$service_name:latest $$service; \
		fi \
	done

terraform-init: ## Initialize Terraform
	cd infra/terraform/environments/dev && terraform init

terraform-plan: ## Plan Terraform changes (ENV=dev|staging|prod)
	@if [ -z "$(ENV)" ]; then ENV=dev; fi; \
	cd infra/terraform/environments/$$ENV && terraform plan

terraform-apply: ## Apply Terraform changes (ENV=dev|staging|prod)
	@if [ -z "$(ENV)" ]; then ENV=dev; fi; \
	cd infra/terraform/environments/$$ENV && terraform apply

deploy-service: ## Deploy a service to Cloud Run (usage: make deploy-service SERVICE=detection ENV=dev)
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE variable is required"; \
		exit 1; \
	fi
	@if [ -z "$(ENV)" ]; then ENV=dev; fi; \
	./scripts/deployment/deploy-service.sh $(SERVICE) $$ENV

setup-dev: install install-libs ## Setup complete development environment
	@echo "Development environment ready!"
	@echo "Run 'make help' to see available commands"

check: lint test ## Run linters and tests
