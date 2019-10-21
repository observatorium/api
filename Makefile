DOCKER_REPO ?= quay.io/observatorium/observatorium
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

default: observatorium
all: clean lint test observatorium

tmp/help.txt: clean build
	mkdir -p tmp
	./observatorium --help &> tmp/help.txt

README.md: tmp/help.txt
	embedmd -w README.md

observatorium: vendor main.go $(wildcard *.go) $(wildcard */*.go)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on GOPROXY=https://proxy.golang.org go build -mod vendor -a -ldflags '-s -w' -o $@ .

build: vendor main.go $(wildcard *.go) $(wildcard */*.go)
	go build -mod=vendor -a -ldflags '-s -w' -o observatorium .

.PHONY: vendor
vendor: go.mod go.sum
	go mod tidy
	go mod vendor

.PHONY: format
format:
	golangci-lint run --fix --enable-all -c .golangci.yml

.PHONY: lint
lint: vendor format
	@fmt_res=$$(gofmt -d -s $$(find . -type f -name '*.go' -not -path './vendor/*' -not -path './jsonnet/vendor/*')); if [ -n "$$fmt_res" ]; then printf '\nGofmt found style issues. Please check the reported issues\nand fix them if necessary before submitting the code for review:\n\n%s' "$$fmt_res"; exit 1; fi
	golangci-lint run -v --enable-all -c .golangci.yml

.PHONY: test
test:
	CGO_ENABLED=1 GO111MODULE=on go test -v -race ./...

.PHONY: clean
clean:
	-rm tmp/help.txt
	-rm observatorium

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
