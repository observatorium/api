SHELL=/usr/bin/env bash -o pipefail

VERSION := $(strip $(shell [ -d .git ] && git describe --always --tags --dirty))
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%S%Z")
VCS_REF := $(strip $(shell [ -d .git ] && git rev-parse --short HEAD))

CONTAINER_CMD:=docker run --rm \
		-u="$(shell id -u):$(shell id -g)" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(PWD):/go/src/github.com/observatorium/observatorium:Z" \
		-w "/go/src/github.com/observatorium/observatorium" \
		-e USER=deadbeef \
		-e GO111MODULE=on \
		quay.io/coreos/jsonnet-ci

BIN_DIR ?= ./tmp/bin
FIRST_GOPATH := $(firstword $(subst :, ,$(shell go env GOPATH)))

default: observatorium
all: clean lint test observatorium

tmp/help.txt: clean build
	mkdir -p tmp
	-./observatorium --help &> tmp/help.txt

README.md: $(EMBEDMD) tmp/help.txt
	$(EMBEDMD) -w README.md

observatorium: vendor main.go $(wildcard *.go) $(wildcard */*.go)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on GOPROXY=https://proxy.golang.org go build -mod vendor -a -ldflags '-s -w' -o $@ .

build: vendor main.go $(wildcard *.go) $(wildcard */*.go)
	go build -mod=vendor -a -ldflags '-s -w' -o observatorium .

.PHONY: vendor
vendor: go.mod go.sum
	go mod tidy
	go mod vendor

.PHONY: format
format: $(GOLANGCILINT) go-fmt
	$(GOLANGCILINT) run --fix --enable-all -c .golangci.yml

.PHONY: go-fmt
go-fmt:
	@fmt_res=$$(gofmt -d -s $$(find . -type f -name '*.go' -not -path './vendor/*' -not -path './jsonnet/vendor/*')); if [ -n "$$fmt_res" ]; then printf '\nGofmt found style issues. Please check the reported issues\nand fix them if necessary before submitting the code for review:\n\n%s' "$$fmt_res"; exit 1; fi

.PHONY: shellcheck
shellcheck: $(SHELLCHECK)
	$(SHELLCHECK) $(shell find . -type f -name "*.sh" -not -path "*vendor*")

.PHONY: lint
lint: $(GOLANGCILINT) vendor format shellcheck
	$(GOLANGCILINT) run -v --enable-all -c .golangci.yml

.PHONY: test
test: test-unit test-integration

.PHONY: test-unit
test-unit:
	CGO_ENABLED=1 GO111MODULE=on go test -v -race -short ./...

.PHONY: test-integration
test-integration: test-dependencies
	PATH=$$PATH:$$(pwd)/$(BIN_DIR):$(FIRST_GOPATH)/bin ./test/integration.sh

.PHONY: clean
clean:
	-rm tmp/help.txt
	-rm -rf tmp/bin
	-rm observatorium

DOCKER_REPO ?= quay.io/observatorium/observatorium

.PHONY: container
container: observatorium Dockerfile
	@docker build --build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg DOCKERFILE_PATH="/Dockerfile" \
		-t $(DOCKER_REPO):$(VERSION) .

.PHONY: container-push-push
container-push: container
	docker push $(DOCKER_REPO):$(VERSION) $(DOCKER_REPO):latest

PROMETHEUS ?= $(BIN_DIR)/prometheus
PROMETHEUS_VERSION ?= 2.14.0
THANOS ?= $(BIN_DIR)/thanos
THANOS_VERSION ?= 0.9.0
UP ?= $(FIRST_GOPATH)/bin/up

GOLANGCILINT ?= $(FIRST_GOPATH)/bin/golangci-lint
GOLANGCILINT_VERSION ?= v1.21.0
EMBEDMD ?= $(FIRST_GOPATH)/bin/embedmd
SHELLCHECK ?= $(BIN_DIR)/shellcheck

test-dependencies: $(PROMETHEUS) $(THANOS) $(UP) $(EMBEDMD) $(GOLANGCILINT) $(SHELLCHECK)

$(PROMETHEUS):
	mkdir -p $(BIN_DIR)
	@echo "Downloading Prometheus"
	curl -L "https://github.com/prometheus/prometheus/releases/download/v$(PROMETHEUS_VERSION)/prometheus-$(PROMETHEUS_VERSION).$$(go env GOOS)-$$(go env GOARCH).tar.gz" | tar --strip-components=1 -xzf - -C $(BIN_DIR)

$(THANOS):
	mkdir -p $(BIN_DIR)
	@echo "Downloading Thanos"
	curl -L "https://github.com/thanos-io/thanos/releases/download/v$(THANOS_VERSION)/thanos-$(THANOS_VERSION).$$(go env GOOS)-$$(go env GOARCH).tar.gz" | tar --strip-components=1 -xzf - -C $(BIN_DIR)

$(UP):
	GO111MODULE=off go get -u github.com/observatorium/up

$(EMBEDMD):
	GO111MODULE=off go get -u github.com/campoy/embedmd

$(GOLANGCILINT):
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCILINT_VERSION)/install.sh \
		| sed -e '/install -d/d' \
		| sh -s -- -b $(FIRST_GOPATH)/bin $(GOLANGCILINT_VERSION)

OS ?= $(shell uname -s | tr '[A-Z]' '[a-z]')
ARCH ?= $(shell uname -m)
$(SHELLCHECK):
	mkdir -p $(BIN_DIR)
	@echo "Downloading Shellcheck"
	curl -L "https://storage.googleapis.com/shellcheck/shellcheck-stable.$(OS).$(ARCH).tar.xz" | tar --strip-components=1 -xzf - -C $(BIN_DIR)
