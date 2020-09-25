SHELL=/usr/bin/env bash -o pipefail
TMP_DIR := $(shell pwd)/tmp
BIN_DIR ?= $(TMP_DIR)/bin
CERT_DIR ?= $(TMP_DIR)/certs
FIRST_GOPATH := $(firstword $(subst :, ,$(shell go env GOPATH)))
OS ?= $(shell uname -s | tr '[A-Z]' '[a-z]')
ARCH ?= $(shell uname -m)

VERSION := $(strip $(shell [ -d .git ] && git describe --always --tags --dirty))
BUILD_DATE := $(shell date -u +"%Y-%m-%d")
BUILD_TIMESTAMP := $(shell date -u +"%Y-%m-%dT%H:%M:%S%Z")
VCS_BRANCH := $(strip $(shell git rev-parse --abbrev-ref HEAD))
VCS_REF := $(strip $(shell [ -d .git ] && git rev-parse --short HEAD))
DOCKER_REPO ?= quay.io/observatorium/observatorium

CONTAINER_CMD := docker run --rm \
		-u="$(shell id -u):$(shell id -g)" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(PWD):/go/src/github.com/observatorium/observatorium:Z" \
		-w "/go/src/github.com/observatorium/observatorium" \
		-e USER=deadbeef \
		-e GO111MODULE=on \
		quay.io/coreos/jsonnet-ci

THANOS ?= $(BIN_DIR)/thanos
THANOS_VERSION ?= 0.13.0
PROMETHEUS ?= $(BIN_DIR)/prometheus
PROMETHEUS_VERSION ?= 2.15.2

LOKI ?= $(BIN_DIR)/loki
LOKI_VERSION ?= 1.5.0
WEBSOCAT ?= $(BIN_DIR)/websocat
WEBSOCAT_VERSION ?= 1.5.0
WEBSOCAT_PKG =
ifeq ($(shell go env GOOS),linux)
	WEBSOCAT_PKG = "websocat_amd64-linux"
else
	WEBSOCAT_PKG = "websocat_mac"
endif

UP ?= $(BIN_DIR)/up
DEX ?= $(BIN_DIR)/dex
OPA ?= $(BIN_DIR)/opa
MOCKPROVIDER ?= $(BIN_DIR)/mockprovider
PROMREMOTEBENCH ?= $(BIN_DIR)/promremotebench
PROMREMOTEBENCH_VERSION ?= 0.8.0
STYX ?= $(BIN_DIR)/styx

GOLANGCILINT ?= $(FIRST_GOPATH)/bin/golangci-lint
GOLANGCILINT_VERSION ?= v1.21.0
EMBEDMD ?= $(BIN_DIR)/embedmd
JSONNET ?= $(BIN_DIR)/jsonnet
JSONNET_FMT ?= $(BIN_DIR)/jsonnetfmt
GOJSONTOYAML ?= $(BIN_DIR)/gojsontoyaml
SHELLCHECK ?= $(BIN_DIR)/shellcheck
GENERATE_TLS_CERT ?= $(BIN_DIR)/generate-tls-cert
KUBEVAL ?= $(BIN_DIR)/kubeval

SERVER_CERT ?= $(CERT_DIR)/server.pem

default: observatorium
all: clean lint test observatorium

tmp/help.txt: observatorium
	./observatorium --help &> tmp/help.txt || true

tmp/load_help.txt:
	-./test/load.sh -h > tmp/load_help.txt 2&>1

README.md: $(EMBEDMD) tmp/help.txt
	$(EMBEDMD) -w README.md

benchmark.md: $(EMBEDMD) tmp/load_help.txt
	-rm -rf ./docs/loadtests
	PATH=$$PATH:$$(pwd)/$(BIN_DIR):$(FIRST_GOPATH)/bin ./test/load.sh -r 300 -c 1000 -m 3 -q 10 -o gnuplot
	$(EMBEDMD) -w docs/benchmark.md

observatorium: vendor main.go $(wildcard *.go) $(wildcard */*.go)
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=amd64 GO111MODULE=on GOPROXY=https://proxy.golang.org go build -mod vendor -a -ldflags '-s -w' -o $@ .

.PHONY: build
build: observatorium

.PHONY: run
run: build $(THANOS) $(DEX) $(LOKI) generate-cert
	PATH=$$PATH:$$(pwd)/$(BIN_DIR):$(FIRST_GOPATH)/bin ./test/run-local.sh

.PHONY: vendor
vendor: go.mod go.sum
	go mod tidy
	go mod vendor

.PHONY: format
format: $(GOLANGCILINT)
	$(GOLANGCILINT) run --fix --enable-all -c .golangci.yml

.PHONY: validate
validate: $(KUBEVAL)
	$(KUBEVAL) examples/manifests/*.yaml

.PHONY: go-fmt
go-fmt:
	@fmt_res=$$(gofmt -d -s $$(find . -type f -name '*.go' -not -path './vendor/*' -not -path './jsonnet/vendor/*' -not -path '${TMP_DIR}/*')); if [ -n "$$fmt_res" ]; then printf '\nGofmt found style issues. Please check the reported issues\nand fix them if necessary before submitting the code for review:\n\n%s' "$$fmt_res"; exit 1; fi

.PHONY: shellcheck
shellcheck: $(SHELLCHECK)
	$(SHELLCHECK) $(shell find . -type f -name "*.sh" -not -path "*vendor*" -not -path "${TMP_DIR}/*")

.PHONY: lint
lint: $(GOLANGCILINT) vendor go-fmt shellcheck jsonnet-fmt
	$(GOLANGCILINT) run -v --enable-all -c .golangci.yml

.PHONY: test
test: build test-unit test-integration

.PHONY: test-unit
test-unit:
	CGO_ENABLED=1 GO111MODULE=on go test -mod vendor -v -race -short ./...

.PHONY: test-integration
test-integration: build integration-test-dependencies generate-cert
	PATH=$$PATH:$$(pwd)/$(BIN_DIR):$(FIRST_GOPATH)/bin ./test/integration.sh

.PHONY: test-load
test-load: build load-test-dependencies
	PATH=$$PATH:$$(pwd)/$(BIN_DIR):$(FIRST_GOPATH)/bin ./test/load.sh

.PHONY: clean
clean:
	-rm tmp/help.txt
	-rm -rf tmp/bin
	-rm observatorium

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

.PHONY: integration-test-dependencies

integration-test-dependencies: $(THANOS) $(UP) $(DEX) $(LOKI) $(WEBSOCAT) $(OPA)

.PHONY: load-test-dependencies
load-test-dependencies: $(PROMREMOTEBENCH) $(PROMETHEUS) $(STYX) $(MOCKPROVIDER)

.PHONY: test-dependencies
test-dependencies: $(THANOS) $(UP) $(EMBEDMD) $(GOLANGCILINT) $(SHELLCHECK)

$(SERVER_CERT): | $(GENERATE_TLS_CERT) $(CERT_DIR)
	cd $(CERT_DIR) && $(GENERATE_TLS_CERT)

# Generate TLS certificates for local development.
generate-cert: $(SERVER_CERT) | $(GENERATE_TLS_CERT)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(CERT_DIR):
	mkdir -p $(CERT_DIR)

$(THANOS): | $(BIN_DIR)
	@echo "Downloading Thanos"
	curl -L "https://github.com/thanos-io/thanos/releases/download/v$(THANOS_VERSION)/thanos-$(THANOS_VERSION).$$(go env GOOS)-$$(go env GOARCH).tar.gz" | tar --strip-components=1 -xzf - -C $(BIN_DIR)

$(PROMETHEUS): | $(BIN_DIR)
	@echo "Downloading Prometheus"
	curl -L "https://github.com/prometheus/prometheus/releases/download/v$(PROMETHEUS_VERSION)/prometheus-$(PROMETHEUS_VERSION).$$(go env GOOS)-$$(go env GOARCH).tar.gz" | tar --strip-components=1 -xzf - -C $(BIN_DIR)

$(LOKI): | $(BIN_DIR)
	@echo "Downloading Loki"
	(loki_pkg="loki-$$(go env GOOS)-$$(go env GOARCH)" && \
	cd $(BIN_DIR) && curl -O -L "https://github.com/grafana/loki/releases/download/v$(LOKI_VERSION)/$$loki_pkg.zip" && \
	unzip $$loki_pkg.zip && \
	mv $$loki_pkg loki && \
	rm $$loki_pkg.zip)

$(WEBSOCAT): | $(BIN_DIR)
	@echo "Downloading Websocat"
	cd $(BIN_DIR) && curl -O -L "https://github.com/vi/websocat/releases/download/v$(WEBSOCAT_VERSION)/$(WEBSOCAT_PKG)" && \
	mv $(WEBSOCAT_PKG) websocat && \
	chmod u+x websocat

$(UP): | vendor $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/observatorium/up/cmd/up

$(DEX): | vendor $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/dexidp/dex/cmd/dex

$(OPA): | vendor $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/open-policy-agent/opa

$(MOCKPROVIDER): | vendor $(BIN_DIR)
	go build -mod=vendor -tags tools -o $@ github.com/observatorium/observatorium/test/mock

$(PROMREMOTEBENCH): | vendor $(BIN_DIR)
	mkdir -p $(TMP_DIR)/promremotebench
	curl -L https://github.com/m3dbx/promremotebench/archive/v$(PROMREMOTEBENCH_VERSION).tar.gz | tar --strip-components=1 -xzf - -C $(TMP_DIR)/promremotebench
	cd $(TMP_DIR)/promremotebench/src && \
		go build ./cmd/promremotebench
	mv $(TMP_DIR)/promremotebench/src/promremotebench $@

$(EMBEDMD): | vendor $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/campoy/embedmd

$(STYX): | vendor $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/go-pluto/styx

$(GOJSONTOYAML): | vendor $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/brancz/gojsontoyaml

$(JSONNET): | vendor $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/google/go-jsonnet/cmd/jsonnet

$(JSONNET_FMT): vendor |  $(BIN_DIR)
	go build -mod=vendor -o $@ github.com/google/go-jsonnet/cmd/jsonnetfmt

$(KUBEVAL): $(BIN_DIR)
	go get -d github.com/instrumenta/kubeval
	go build -o $@ github.com/instrumenta/kubeval

$(GOLANGCILINT):
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCILINT_VERSION)/install.sh \
		| sed -e '/install -d/d' \
		| sh -s -- -b $(FIRST_GOPATH)/bin $(GOLANGCILINT_VERSION)

$(SHELLCHECK): $(BIN_DIR)
	curl -sNL "https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.$(OS).$(ARCH).tar.xz" | tar --strip-components=1 -xJf - -C $(BIN_DIR)

$(GENERATE_TLS_CERT): | vendor $(BIN_DIR)
	# A thin wrapper around github.com/cloudflare/cfssl
	go build -mod=vendor -tags tools -o $@ github.com/observatorium/observatorium/test/tls

# Jsonnet and Example manifests

CONTAINER_CMD:=docker run --rm \
		-u="$(shell id -u):$(shell id -g)" \
		-v "$(shell go env GOCACHE):/.cache/go-build" \
		-v "$(PWD):/go/src/github.com/observatorium/observatorium:Z" \
		-w "/go/src/github.com/observatorium/observatorium" \
		-e USER=deadbeef \
		-e GO111MODULE=on \
		quay.io/coreos/jsonnet-ci

.PHONY: generate
generate: examples/manifests README.md

.PHONY: generate-in-docker
generate-in-docker:
	@echo ">> Compiling assets and generating Kubernetes manifests"
	$(CONTAINER_CMD) make $(MFLAGS) generate

examples/manifests: examples/main.jsonnet jsonnet/lib/* | $(JSONNET) $(GOJSONTOYAML)
	@rm -rf examples/manifests
	@mkdir -p examples/manifests
	$(JSONNET) -m examples/manifests examples/main.jsonnet | xargs -I{} sh -c 'cat {} | $(GOJSONTOYAML) > {}.yaml && rm -f {}' -- {}

JSONNET_SRC = $(shell find . -name 'vendor' -prune -o -name 'examples/vendor' -prune -o -name 'tmp' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print)
JSONNET_FMT_CMD := $(JSONNET_FMT) -n 2 --max-blank-lines 2 --string-style s --comment-style s

.PHONY: jsonnet-fmt
jsonnet-fmt: | $(JSONNET_FMT)
	PATH=$$PATH:$$(pwd)/$(BIN_DIR) echo ${JSONNET_SRC} | xargs -n 1 -- $(JSONNET_FMT_CMD) -i
