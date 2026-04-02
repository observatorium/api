#!/usr/bin/make -f

# Mixed Authentication KIND Test Environment
# This Makefile provides a complete test environment for mixed authentication

CLUSTER_NAME := observatorium-auth-test
IMAGE_NAME := observatorium-api-auth-test:latest
NAMESPACE := proxy

# Environment setup
.PHONY: setup
setup: cluster-bootstrap deploy ## Complete environment setup

.PHONY: cluster-bootstrap
cluster-bootstrap: cluster-create deploy-infrastructure extract-certs-and-config ## Bootstrap cluster infrastructure

.PHONY: deploy
deploy: deploy-applications ## Deploy applications with extracted configs

.PHONY: teardown
teardown: cluster-delete clean-testdata ## Clean up entire environment

# KIND cluster management
.PHONY: cluster-create
cluster-create: ## Create KIND cluster for mixed auth testing
	@echo "Creating KIND cluster: $(CLUSTER_NAME)"
	kind create cluster --name $(CLUSTER_NAME)
	@echo "✓ KIND cluster created successfully"

.PHONY: cluster-delete
cluster-delete: ## Delete KIND cluster
	@echo "Deleting KIND cluster: $(CLUSTER_NAME)"
	kind delete cluster --name $(CLUSTER_NAME)
	@echo "✓ KIND cluster deleted"

.PHONY: cluster-info
cluster-info: ## Show cluster information
	@echo "KIND cluster information:"
	kubectl cluster-info --context kind-$(CLUSTER_NAME)
	@echo ""
	@echo "Nodes:"
	kubectl get nodes --context kind-$(CLUSTER_NAME)

# Image management
.PHONY: build-image
build-image: ## Build observatorium API image
	@if ! docker image inspect $(IMAGE_NAME) >/dev/null 2>&1; then \
		echo "Building observatorium API image..."; \
		cd ../.. && make container; \
		docker tag quay.io/observatorium/api:latest $(IMAGE_NAME); \
		echo "✓ Image built: $(IMAGE_NAME)"; \
	else \
		echo "✓ Image $(IMAGE_NAME) already exists, skipping build"; \
	fi

.PHONY: load-images
load-images: build-image ## Load observatorium API image into KIND cluster
	@echo "Loading observatorium API image into KIND cluster..."
	kind load docker-image $(IMAGE_NAME) --name $(CLUSTER_NAME)
	@echo "✓ Image loaded successfully"

# Infrastructure deployment (bootstrap phase)
.PHONY: deploy-infrastructure
deploy-infrastructure: deploy-cert-manager deploy-certificates deploy-backends deploy-dex ## Deploy cluster infrastructure

.PHONY: deploy-backends
deploy-backends: ## Deploy backend services
	@echo "Deploying backend services..."
	kubectl apply --context kind-$(CLUSTER_NAME) -f resources/backends.yaml
	@echo "Waiting for backends to be ready..."
	kubectl wait --context kind-$(CLUSTER_NAME) --for=condition=Available=True deploy/api-proxy -n $(NAMESPACE) --timeout=300s
	kubectl wait --context kind-$(CLUSTER_NAME) --for=condition=Available=True deploy/httpbin-metrics -n $(NAMESPACE) --timeout=300s
	@echo "✓ Backend services deployed successfully"

.PHONY: deploy-dex
deploy-dex: ## Deploy Dex OIDC provider
	@echo "Deploying Dex OIDC provider..."
	kubectl apply --context kind-$(CLUSTER_NAME) -f resources/dex.yaml
	@echo "Waiting for Dex to be ready..."
	kubectl wait --context kind-$(CLUSTER_NAME) --for=condition=Available=True deploy/dex -n $(NAMESPACE) --timeout=300s
	@echo "✓ Dex deployed successfully"

.PHONY: deploy-cert-manager
deploy-cert-manager: ## Deploy cert-manager
	@echo "Deploying official cert-manager..."
	kubectl apply --context kind-$(CLUSTER_NAME) -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
	@echo "Waiting for cert-manager to be ready..."
	kubectl wait --context kind-$(CLUSTER_NAME) --for=condition=Available=True deploy/cert-manager -n cert-manager --timeout=300s
	kubectl wait --context kind-$(CLUSTER_NAME) --for=condition=Available=True deploy/cert-manager-webhook -n cert-manager --timeout=300s
	@echo "✓ cert-manager deployed successfully"

.PHONY: deploy-certificates
deploy-certificates: ## Deploy TLS certificates
	@echo "Deploying TLS certificates..."
	kubectl apply --context kind-$(CLUSTER_NAME) -f resources/certificates.yaml
	@echo "Waiting for certificates to be ready..."
	sleep 30  # Give time for certificate generation
	@echo "✓ TLS certificates deployed"

# Extract certificates and configuration from cluster
.PHONY: extract-certs-and-config
extract-certs-and-config: ## Extract certificates and config from cluster
	@echo "Running config extraction script..."
	./extract-config.sh
	@echo "✓ Configuration extraction complete"

# Application deployment (deploy phase)
.PHONY: deploy-applications
deploy-applications: load-images deploy-services deploy-api ## Deploy applications using extracted configs

.PHONY: deploy-services
deploy-services: ## Deploy services and ingress routing
	@echo "Deploying services and ingress routing..."
	kubectl apply --context kind-$(CLUSTER_NAME) -f resources/services.yaml
	@echo "✓ Services and ingress routing deployed"


.PHONY: deploy-api
deploy-api: ## Deploy Observatorium API with mixed authentication
	@echo "Deploying Observatorium API with mixed authentication..."
	kubectl apply --context kind-$(CLUSTER_NAME) -f testdata/observatorium-api.yaml
	@echo "Waiting for API to be ready..."
	kubectl wait --context kind-$(CLUSTER_NAME) --for=condition=Available=True deploy/observatorium-api -n $(NAMESPACE) --timeout=300s
	@echo "✓ Observatorium API deployed successfully"


# Testing
.PHONY: test
test: ## Run mixed authentication e2e tests
	@echo "Running mixed authentication e2e tests..."
	go run e2e.go
	@echo "✓ Tests completed"

.PHONY: test-comprehensive
test-comprehensive: ## Run comprehensive KIND e2e tests
	@echo "Running comprehensive KIND e2e tests..."
	go test -v -run TestMixedAuthenticationE2E ./...
	@echo "✓ Comprehensive tests completed"

.PHONY: test-production
test-production: ## Run production e2e tests against real deployment
	@echo "Running production e2e tests..."
	cd ../.. && go test -v ./test/e2e -run TestMixedAuthenticationProduction
	@echo "✓ Production tests completed"

# Clean up resources
.PHONY: clean-testdata
clean-testdata: ## Clean up extracted certificates and configs
	@echo "Cleaning up testdata..."
	rm -rf testdata/
	@echo "✓ Testdata cleaned"

.PHONY: clean
clean: clean-testdata ## Clean up test artifacts
	@echo "Cleaning up test artifacts..."
	rm -f *.crt *.key *.pem
	@echo "✓ Test artifacts cleaned"

.PHONY: reset
reset: teardown setup ## Reset entire environment
	@echo "✓ Environment reset complete"
