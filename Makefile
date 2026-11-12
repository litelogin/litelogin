# LiteLogin build, test and deploy targets. Run `make help` for a list.

# Lambda functions to build. Each one is ./cmd/<name>, packaged as dist/<name>.zip.
FUNCTIONS := auth rotate admin worker

# Terraform-compatible CLI: OpenTofu if installed, otherwise Terraform. Override with TF=...
TF ?= $(shell command -v tofu >/dev/null 2>&1 && echo tofu || echo terraform)
COMPOSE ?= docker compose

# Local development settings.
LOCAL_DYNAMODB_ENDPOINT ?= http://localhost:18000
LOCAL_ENV := \
	LITELOGIN_DYNAMODB_ENDPOINT=$(LOCAL_DYNAMODB_ENDPOINT) \
	LITELOGIN_CONFIG_TABLE=litelogin-local-config \
	LITELOGIN_SESSION_TABLE=litelogin-local-session

# Build, test and scan with the toolchain go.mod pins, whatever Go is
# installed (it downloads it if needed), so local builds are byte-for-byte
# the same as the pipeline's and get its security fixes.
export GOTOOLCHAIN := $(shell sed -n 's/^toolchain //p' go.mod)

# Tool versions.
GOVULNCHECK_VERSION := v1.9.0

GO_BUILD_ENV := GOOS=linux GOARCH=arm64 CGO_ENABLED=0
GO_BUILD_FLAGS := -tags lambda.norpc -trimpath -ldflags="-s -w -buildid="

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

.PHONY: build
build: ## Build every Lambda as dist/<name>/bootstrap (linux/arm64)
	@for fn in $(FUNCTIONS); do \
		echo "build $$fn"; \
		$(GO_BUILD_ENV) go build $(GO_BUILD_FLAGS) -o dist/$$fn/bootstrap ./cmd/$$fn || exit 1; \
	done

.PHONY: package
package: build ## Zip every Lambda as dist/<name>.zip
	@for fn in $(FUNCTIONS); do \
		echo "package $$fn"; \
		touch -t 198001010000 dist/$$fn/bootstrap; \
		rm -f dist/$$fn.zip; \
		(cd dist/$$fn && zip -q -X ../$$fn.zip bootstrap) || exit 1; \
	done

.PHONY: test
test: ## Run unit tests (integration tests are skipped)
	go test -race ./...

.PHONY: test-integration
test-integration: ## Run all tests, including DynamoDB Local integration tests
	$(LOCAL_ENV) go test -race -count=1 ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: vet ## Run golangci-lint
	golangci-lint run

.PHONY: vuln
vuln: ## Check dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: tf-fmt
tf-fmt: ## Format Terraform files
	$(TF) fmt -recursive infra

.PHONY: tf-validate
tf-validate: ## Validate the Terraform environments (no backend, no AWS calls)
	@for env in infra/envs/*/; do \
		echo "validate $$env"; \
		(cd $$env && $(TF) init -backend=false -input=false >/dev/null && $(TF) validate) || exit 1; \
	done

.PHONY: deploy-dev
deploy-dev: package ## Build, package and apply the dev environment
	cd infra/envs/dev && $(TF) init -backend-config=backend.hcl -input=false && $(TF) apply

.PHONY: local-up
local-up: ## Start DynamoDB Local
	$(COMPOSE) up -d

.PHONY: local-down
local-down: ## Stop DynamoDB Local (data is in memory and is discarded)
	$(COMPOSE) down

.PHONY: local-tables
local-tables: ## Create the tables in DynamoDB Local
	$(LOCAL_ENV) go run ./cmd/devtables

.PHONY: run-auth
run-auth: ## Run the Auth Lambda as a local HTTP server on localhost:8080
	$(LOCAL_ENV) go run ./cmd/auth

.PHONY: run-admin
run-admin: ## Run the Admin API as a local HTTP server on localhost:8081 (no auth: use --endpoint http://localhost:8081)
	$(LOCAL_ENV) LITELOGIN_DEFAULT_HOST_DOMAIN=litelogin.localhost go run ./cmd/admin

.PHONY: cli
cli: ## Build the litelogin CLI for this machine as dist/litelogin
	go build -trimpath -o dist/litelogin ./cmd/litelogin

.PHONY: clean
clean: ## Remove build output
	rm -rf dist
