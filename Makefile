include .bingo/Variables.mk

SHELL=/usr/bin/env bash -o pipefail
TMP_DIR := $(shell pwd)/tmp
BIN_DIR ?= $(TMP_DIR)/bin
FIRST_GOPATH := $(firstword $(subst :, ,$(shell go env GOPATH)))
OS ?= $(shell uname -s | tr '[A-Z]' '[a-z]')
ARCH ?= $(shell uname -m)
GOARCH ?= $(shell go env GOARCH)
BIN_NAME ?= observatorium-api

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

$(BIN_NAME): deps main.go $(wildcard *.go) $(wildcard */*.go)
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(GOARCH) GO111MODULE=on GOPROXY=https://proxy.golang.org go build -a -ldflags '-s -w' -o $(BIN_NAME) .

.PHONY: build
build: $(BIN_NAME)

.PHONY: deps
deps: go.mod go.sum
	go mod tidy
	go mod download
	go mod verify

.PHONY: format
format: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run --fix --enable-all -c .golangci.yml

.PHONY: shellcheck
shellcheck: $(SHELLCHECK)
	$(SHELLCHECK) $(shell find . -type f -name "*.sh" -not -path "*vendor*" -not -path "*tmp*")

.PHONY: lint
lint: $(GOLANGCI_LINT) deps shellcheck jsonnet-fmt
	$(GOLANGCI_LINT) run -v --enable-all -c .golangci.yml

.PHONY: test
test: build test-unit

.PHONY: test-unit
test-unit:
	CGO_ENABLED=1 GO111MODULE=on go test -v -race -short $(shell go list ./... | grep -v api/test/e2e)

.PHONY: test-e2e
test-e2e: container-test
	CGO_ENABLED=1 GO111MODULE=on go test -v -race -short --tags integration ./test/e2e

.PHONY: test-interactive
test-interactive: container-test
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
container-test: build
	@docker build \
		-f Dockerfile.e2e-test \
		-t $(DOCKER_REPO):local_e2e_test .

.PHONY: container
container: Dockerfile
	@docker build --build-arg BUILD_DATE="$(BUILD_TIMESTAMP)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg VCS_BRANCH="$(VCS_BRANCH)" \
		--build-arg DOCKERFILE_PATH="/Dockerfile" \
		-t $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION) .
	@docker tag $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION) $(DOCKER_REPO):latest

.PHONY: container-push
container-push: container
	docker push $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION)
	docker push $(DOCKER_REPO):latest

.PHONY: container-release
container-release: VERSION_TAG = $(strip $(shell [ -d .git ] && git tag --points-at HEAD))
container-release: container
	# https://git-scm.com/docs/git-tag#Documentation/git-tag.txt---points-atltobjectgt
	@docker tag $(DOCKER_REPO):$(VCS_BRANCH)-$(BUILD_DATE)-$(VERSION) $(DOCKER_REPO):$(VERSION_TAG)
	docker push $(DOCKER_REPO):$(VERSION_TAG)
	docker push $(DOCKER_REPO):latest

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
	curl -sNL "https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.$(OS).$(ARCH).tar.xz" | tar --strip-components=1 -xJf - -C $(BIN_DIR)

$(MOCKPROVIDER): | deps $(BIN_DIR)
	go build -tags tools -o $@ github.com/observatorium/api/test/mock

$(PROTOC): $(TMP_DIR) $(BIN_DIR)
	@PROTOC_VERSION="$(PROTOC_VERSION)" TMP_DIR="$(TMP_DIR)" BIN_DIR="$(BIN_DIR)" scripts/install_protoc.sh

# Jsonnet and Example manifests.

MANIFESTS := examples/manifests

.PHONY: generate
generate: ${MANIFESTS} README.md

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
