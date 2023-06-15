include .bingo/Variables.mk

SHELL=/usr/bin/env bash -o pipefail
TMP_DIR := $(shell pwd)/tmp
BIN_DIR ?= $(TMP_DIR)/bin
FIRST_GOPATH := $(firstword $(subst :, ,$(shell go env GOPATH)))
OS ?= $(shell go env GOOS)
ARCH ?= $(shell go env GOARCH)
BIN_NAME ?= observatorium-api
FILES_TO_FMT ?= $(filter-out ./ratelimit/gubernator/gubernator.pb.go, $(shell find . -path ./vendor -not -prune -o -name '*.go' -print))

VERSION := $(strip $(shell [ -d .git ] && git describe --always --tags --dirty))
BUILD_DATE := $(shell date -u +"%Y-%m-%d")
BUILD_TIMESTAMP := $(shell date -u +"%Y-%m-%dT%H:%M:%S%Z")
VCS_BRANCH := $(strip $(shell git rev-parse --abbrev-ref HEAD | tr / -))
VCS_REF := $(strip $(shell [ -d .git ] && git rev-parse --short HEAD))
DOCKER_REPO ?= quay.io/observatorium/api

CONTAINER_CMD := docker run --rm \
		-u="$(shell id -u):$(shell id -g)" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(PWD):/go/src/github.com/observatorium/api:Z" \
		-w "/go/src/github.com/observatorium/api" \
		-e USER=deadbeef \
		-e GO111MODULE=on \
		quay.io/coreos/jsonnet-ci

PROMETHEUS ?= $(BIN_DIR)/prometheus
PROMETHEUS_VERSION ?= 2.15.2
PROMREMOTEBENCH ?= $(BIN_DIR)/promremotebench
PROMREMOTEBENCH_VERSION ?= 0.8.0
SHELLCHECK ?= $(BIN_DIR)/shellcheck
MOCKPROVIDER ?= $(BIN_DIR)/mockprovider

PROTOC ?= $(TMP_DIR)/protoc
PROTOC_VERSION ?= 3.13.0

GIT ?= $(shell which git)
ifeq (,$(shell which podman 2>/dev/null))
OCI_BIN ?= docker
else
OCI_BIN ?= podman
endif

define require_clean_work_tree
	@git update-index -q --ignore-submodules --refresh

    @if ! git diff-files --quiet --ignore-submodules --; then \
        echo >&2 "$1: you have unstaged changes."; \
        git diff-files --name-status -r --ignore-submodules -- >&2; \
        echo >&2 "Please commit or stash them."; \
        exit 1; \
    fi

    @if ! git diff-index --cached --quiet HEAD --ignore-submodules --; then \
        echo >&2 "$1: your index contains uncommitted changes."; \
        git diff-index --cached --name-status -r --ignore-submodules HEAD -- >&2; \
        echo >&2 "Please commit or stash them."; \
        exit 1; \
    fi

endef

default: $(BIN_NAME)
all: clean lint test $(BIN_NAME) generate validate

tmp/help.txt: $(BIN_NAME) $(TMP_DIR)
	./$(BIN_NAME) --help &> $(TMP_DIR)/help.txt || true

tmp/load_help.txt: $(TMP_DIR)
	-./test/load.sh -h > $(TMP_DIR)/load_help.txt 2&>1

README.md: $(EMBEDMD) tmp/help.txt
	$(EMBEDMD) -w README.md

benchmark.md: $(EMBEDMD) tmp/load_help.txt
	-rm -rf ./docs/loadtests
	PATH=$$PATH:$(BIN_DIR):$(FIRST_GOPATH)/bin ./test/load.sh -r 300 -c 1000 -m 3 -q 10 -o gnuplot
	$(EMBEDMD) -w docs/benchmark.md

$(BIN_NAME): deps main.go rules/rules.go $(wildcard *.go) $(wildcard */*.go)
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) GO111MODULE=on GOPROXY=https://proxy.golang.org go build -a -ldflags '-s -w' -o $(BIN_NAME) .

%.y.go: %.y | $(GOYACC)
	$(GOYACC) -p $(basename $(notdir $<)) -o $@ $<
	sed -i.back '/^\/\/line/ d' $@
	rm ${@}.back

.PHONY: build
build: $(BIN_NAME)

.PHONY: deps
deps: go.mod go.sum
	go mod tidy
	go mod download
	go mod verify

.PHONY: format
format: ## Formats Go code.
format: $(GOIMPORTS) $(GOLANGCI_LINT)
	@echo ">> formatting code"
	@gofmt -s -w $(FILES_TO_FMT)
	@$(GOIMPORTS) -w $(FILES_TO_FMT)

.PHONY: check-git
check-git:
ifneq ($(GIT),)
	@test -x $(GIT) || (echo >&2 "No git executable binary found at $(GIT)."; exit 1)
else
	@echo >&2 "No git binary found."; exit 1
endif

.PHONY: shellcheck
shellcheck: $(SHELLCHECK)
	$(SHELLCHECK) $(shell find . -type f -name "*.sh" -not -path "*vendor*" -not -path "*tmp*")

.PHONY: lint
lint: ## Runs various static analysis against our code.
lint: $(FAILLINT) $(GOLANGCI_LINT) $(MISSPELL) generate format deps build check-git shellcheck jsonnet-fmt
	$(call require_clean_work_tree,'detected not clean work tree before running lint, previous job changed something?')
	@echo ">> verifying modules being imported"
	@$(FAILLINT) -paths "fmt.{Print,Printf,Println},io/ioutil.{Discard,NopCloser,ReadAll,ReadDir,ReadFile,TempDir,TempFile,Writefile}" -ignore-tests ./...
	@echo ">> examining all of the Go files"
	@go vet -stdmethods=false ./...
	@echo ">> linting all of the Go files GOGC=${GOGC}"
	@$(GOLANGCI_LINT) run
	@echo ">> detecting misspells"
	@find . -type f | grep -v vendor/ | grep -vE '\./\..*' | xargs $(MISSPELL) -error
	$(call require_clean_work_tree,'detected files without copyright, run make lint and commit changes')

.PHONY: test
test: build test-unit

.PHONY: test-unit
test-unit:
	CGO_ENABLED=1 GO111MODULE=on go test -v -race -short $(shell go list ./... | grep -v api/test/e2e)

.PHONY: test-e2e
test-e2e: container-test
	@rm -rf test/e2e/e2e_*
	CGO_ENABLED=1 GO111MODULE=on go test -v -race -short -tags integration ./test/e2e

.PHONY: test-interactive
test-interactive: container-test
	@rm -rf test/e2e/e2e_*
	CGO_ENABLED=1 GO111MODULE=on go test -v -tags interactive -test.timeout=9999m ./test/e2e

.PHONY: test-load
test-load: build load-test-dependencies
	PROMREMOTEBENCH=$(PROMREMOTEBENCH) PROMETHEUS=$(PROMETHEUS) STYX=$(STYX) MOCKPROVIDER=$(MOCKPROVIDER) ./test/load.sh

.PHONY: clean
clean:
	-rm tmp/help.txt
	-rm -rf tmp/bin
	-rm -rf tmp/src
	-rm $(BIN_NAME)

ratelimit/gubernator/proto/google:
	mkdir -p $(TMP_DIR)/src/grpc-gateway
	mkdir -p $(shell dirname $@)
	curl -L "https://github.com/grpc-ecosystem/grpc-gateway/archive/master.tar.gz" | tar --strip-components=1 -xzf - -C $(TMP_DIR)/src/grpc-gateway
	mv $(TMP_DIR)/src/grpc-gateway/third_party/googleapis/google $@

ratelimit/gubernator/gubernator.proto:
	curl -L -o ratelimit/gubernator/gubernator.proto "https://raw.githubusercontent.com/mailgun/gubernator/master/proto/gubernator.proto"

.PHONY: proto
proto: ratelimit/gubernator/proto/google ratelimit/gubernator/gubernator.proto $(PROTOC) $(PROTOC_GEN_GO) $(BIN_DIR)
	@cp -f $(PROTOC_GEN_GO) $(BIN_DIR)/protoc-gen-go
	PATH=$$PATH:$(BIN_DIR):$(FIRST_GOPATH)/bin scripts/generate_proto.sh

.PHONY: container-test
container-test: 
	$(OCI_BIN) build \
		--build-arg BUILD_DATE="$(BUILD_TIMESTAMP)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg VCS_BRANCH="$(VCS_BRANCH)" \
		--build-arg DOCKERFILE_PATH="/Dockerfile.e2e-test" \
		-t $(DOCKER_REPO):local_e2e_test  \
		-f Dockerfile.e2e-test \
		.

.PHONY: container
container: Dockerfile
	$(OCI_BIN) build \
		--build-arg BUILD_DATE="$(BUILD_TIMESTAMP)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg VCS_BRANCH="$(VCS_BRANCH)" \
		--build-arg DOCKERFILE_PATH="/Dockerfile" \
		-t $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION) .
	$(OCI_BIN) tag $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION) $(DOCKER_REPO):latest

.PHONY: container-build
container-build:
	git update-index --refresh
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--cache-to type=local,dest=./.buildxcache/ \
	    --build-arg BUILD_DATE="$(BUILD_TIMESTAMP)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg VCS_BRANCH="$(VCS_BRANCH)" \
		--build-arg DOCKERFILE_PATH="/Dockerfile" \
		-t $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION) \
		-t $(DOCKER_REPO):latest \
		.

.PHONY: container-build-push
container-build-push:
	git update-index --refresh
	docker buildx build \
		--push \
		--platform linux/amd64,linux/arm64 \
		--cache-to type=local,dest=./.buildxcache/ \
	    --build-arg BUILD_DATE="$(BUILD_TIMESTAMP)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg VCS_BRANCH="$(VCS_BRANCH)" \
		--build-arg DOCKERFILE_PATH="/Dockerfile" \
		-t $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION) \
		-t $(DOCKER_REPO):latest \
		.

.PHONY: conditional-container-build-push
conditional-container-build-push:
	build/conditional-container-push.sh $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION)

.PHONY: container-release-build-push
container-release-build-push: VERSION_TAG = $(strip $(shell [ -d .git ] && git tag --points-at HEAD))
container-release-build-push: container-build-push
	# https://git-scm.com/docs/git-tag#Documentation/git-tag.txt---points-atltobjectgt
	@docker buildx build \
		--push \
		--platform linux/amd64,linux/arm64 \
		--cache-from type=local,src=./.buildxcache/ \
	    --build-arg BUILD_DATE="$(BUILD_TIMESTAMP)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg VCS_BRANCH="$(VCS_BRANCH)" \
		--build-arg DOCKERFILE_PATH="/Dockerfile" \
		-t $(DOCKER_REPO):$(VERSION_TAG) \
		-t $(DOCKER_REPO):latest \
		.

.PHONY: load-test-dependencies
load-test-dependencies: $(PROMREMOTEBENCH) $(PROMETHEUS) $(STYX) $(MOCKPROVIDER)

$(TMP_DIR):
	mkdir -p $(TMP_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(PROMETHEUS): | $(BIN_DIR)
	@echo "Downloading Prometheus"
	curl -L "https://github.com/prometheus/prometheus/releases/download/v$(PROMETHEUS_VERSION)/prometheus-$(PROMETHEUS_VERSION).$$(go env GOOS)-$$(go env GOARCH).tar.gz" | tar --strip-components=1 -xzf - -C $(BIN_DIR)

$(PROMREMOTEBENCH): | deps $(BIN_DIR)
	mkdir -p $(TMP_DIR)/src/promremotebench
	curl -L https://github.com/m3dbx/promremotebench/archive/v$(PROMREMOTEBENCH_VERSION).tar.gz | tar --strip-components=1 -xzf - -C $(TMP_DIR)/src/promremotebench
	cd $(TMP_DIR)/src/promremotebench && \
		go build ./cmd/promremotebench
	mv $(TMP_DIR)/src/promremotebench/promremotebench $@

$(SHELLCHECK): $(BIN_DIR)
	curl -sNL "https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.$(OS).$(shell uname -m).tar.xz" | tar --strip-components=1 -xJf - -C $(BIN_DIR)

$(MOCKPROVIDER): | deps $(BIN_DIR)
	go build -tags tools -o $@ github.com/observatorium/api/test/mock

$(PROTOC): $(TMP_DIR) $(BIN_DIR)
	@PROTOC_VERSION="$(PROTOC_VERSION)" TMP_DIR="$(TMP_DIR)" BIN_DIR="$(BIN_DIR)" scripts/install_protoc.sh

# Jsonnet and Example manifests.

MANIFESTS := examples/manifests

.PHONY: generate
generate: ${MANIFESTS} rules/rules.go gen-oapi-client README.md

.PHONY: ${MANIFESTS}
${MANIFESTS}: examples/main.jsonnet jsonnet/lib/* | $(JSONNET) $(GOJSONTOYAML)
	@rm -rf ${MANIFESTS}
	@mkdir -p ${MANIFESTS}
	$(JSONNET) -m ${MANIFESTS} examples/main.jsonnet | xargs -I{} sh -c 'cat {} | $(GOJSONTOYAML) > {}.yaml && rm -f {}' -- {

.PHONY: validate
validate: $(KUBEVAL)
	$(KUBEVAL) ${MANIFESTS}/*.yaml

JSONNET_SRC = $(shell find . -name 'vendor' -prune -o -name 'examples/vendor' -prune -o -name 'tmp' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print)
JSONNETFMT_CMD := $(JSONNETFMT) -n 2 --max-blank-lines 2 --string-style s --comment-style s

.PHONY: jsonnet-fmt
jsonnet-fmt: | $(JSONNETFMT)
	PATH=$$PATH:$(BIN_DIR):$(FIRST_GOPATH)/bin echo ${JSONNET_SRC} | xargs -n 1 -- $(JSONNETFMT_CMD) -i

rules/rules.go: $(OAPI_CODEGEN) rules/spec.yaml
	$(OAPI_CODEGEN) -generate types,client,chi-server -package rules rules/spec.yaml | sed 's|gopkg.in/yaml.v2|github.com/ghodss/yaml|g' | gofmt -s > $@

client/client.gen.go: $(OAPI_CODEGEN) client/spec.yaml
	$(OAPI_CODEGEN) -generate types,client -import-mapping="./parameters/parameters.yaml:github.com/observatorium/api/client/parameters,./models/models.yaml:github.com/observatorium/api/client/models,./responses/responses.yaml:github.com/observatorium/api/client/responses" -package client client/spec.yaml | sed 's|gopkg.in/yaml.v2|github.com/ghodss/yaml|g' | gofmt -s > $@

client/parameters/parameters.gen.go: $(OAPI_CODEGEN) client/parameters/parameters.yaml
	$(OAPI_CODEGEN) -generate types,skip-prune -package parameters client/parameters/parameters.yaml | sed 's|gopkg.in/yaml.v2|github.com/ghodss/yaml|g' | gofmt -s > $@

client/models/models.gen.go: $(OAPI_CODEGEN) client/models/models.yaml
	$(OAPI_CODEGEN) -generate types,skip-prune -package models client/models/models.yaml | sed 's|gopkg.in/yaml.v2|github.com/ghodss/yaml|g' | gofmt -s > $@

client/responses/responses.gen.go: $(OAPI_CODEGEN) client/responses/responses.yaml
	$(OAPI_CODEGEN) -generate types,skip-prune -import-mapping="../models/models.yaml:github.com/observatorium/api/client/models" -package responses client/responses/responses.yaml | sed 's|gopkg.in/yaml.v2|github.com/ghodss/yaml|g' | gofmt -s > $@

gen-oapi-client: 
	$(MAKE) client/parameters/parameters.gen.go
	$(MAKE) client/models/models.gen.go
	$(MAKE) client/responses/responses.gen.go
	$(MAKE) client/client.gen.go
