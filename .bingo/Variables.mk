# Auto generated binary variables helper managed by https://github.com/bwplotka/bingo v0.2.2. DO NOT EDIT.
# All tools are designed to be build inside $GOBIN.
GOPATH ?= $(shell go env GOPATH)
GOBIN  ?= $(firstword $(subst :, ,${GOPATH}))/bin
GO     ?= $(shell which go)

# Bellow generated variables ensure that every time a tool under each variable is invoked, the correct version
# will be used; reinstalling only if needed.
# For example for dex variable:
#
# In your main Makefile (for non array binaries):
#
#include .bingo/Variables.mk # Assuming -dir was set to .bingo .
#
#command: $(DEX)
#	@echo "Running dex"
#	@$(DEX) <flags/args..>
#
DEX := $(GOBIN)/dex-v2.13.0+incompatible
$(DEX): .bingo/dex.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/dex-v2.13.0+incompatible"
	@cd .bingo && $(GO) build -modfile=dex.mod -o=$(GOBIN)/dex-v2.13.0+incompatible "github.com/dexidp/dex/cmd/dex"

EMBEDMD := $(GOBIN)/embedmd-v1.0.0
$(EMBEDMD): .bingo/embedmd.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/embedmd-v1.0.0"
	@cd .bingo && $(GO) build -modfile=embedmd.mod -o=$(GOBIN)/embedmd-v1.0.0 "github.com/campoy/embedmd"

GOJSONTOYAML := $(GOBIN)/gojsontoyaml-v0.0.0-20200602132005-3697ded27e8c
$(GOJSONTOYAML): .bingo/gojsontoyaml.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/gojsontoyaml-v0.0.0-20200602132005-3697ded27e8c"
	@cd .bingo && $(GO) build -modfile=gojsontoyaml.mod -o=$(GOBIN)/gojsontoyaml-v0.0.0-20200602132005-3697ded27e8c "github.com/brancz/gojsontoyaml"

GOLANGCI_LINT := $(GOBIN)/golangci-lint-v1.21.0
$(GOLANGCI_LINT): .bingo/golangci-lint.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/golangci-lint-v1.21.0"
	@cd .bingo && $(GO) build -modfile=golangci-lint.mod -o=$(GOBIN)/golangci-lint-v1.21.0 "github.com/golangci/golangci-lint/cmd/golangci-lint"

JB := $(GOBIN)/jb-v0.4.0
$(JB): .bingo/jb.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/jb-v0.4.0"
	@cd .bingo && $(GO) build -modfile=jb.mod -o=$(GOBIN)/jb-v0.4.0 "github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb"

JSONNET := $(GOBIN)/jsonnet-v0.16.0
$(JSONNET): .bingo/jsonnet.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/jsonnet-v0.16.0"
	@cd .bingo && $(GO) build -modfile=jsonnet.mod -o=$(GOBIN)/jsonnet-v0.16.0 "github.com/google/go-jsonnet/cmd/jsonnet"

JSONNETFMT := $(GOBIN)/jsonnetfmt-v0.16.0
$(JSONNETFMT): .bingo/jsonnetfmt.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/jsonnetfmt-v0.16.0"
	@cd .bingo && $(GO) build -modfile=jsonnetfmt.mod -o=$(GOBIN)/jsonnetfmt-v0.16.0 "github.com/google/go-jsonnet/cmd/jsonnetfmt"

KUBEVAL := $(GOBIN)/kubeval-v0.0.0-20201005082916-38668c6c5b23
$(KUBEVAL): .bingo/kubeval.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/kubeval-v0.0.0-20201005082916-38668c6c5b23"
	@cd .bingo && $(GO) build -modfile=kubeval.mod -o=$(GOBIN)/kubeval-v0.0.0-20201005082916-38668c6c5b23 "github.com/instrumenta/kubeval"

OPA := $(GOBIN)/opa-v0.23.2
$(OPA): .bingo/opa.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/opa-v0.23.2"
	@cd .bingo && $(GO) build -modfile=opa.mod -o=$(GOBIN)/opa-v0.23.2 "github.com/open-policy-agent/opa"

STYX := $(GOBIN)/styx-v0.0.0-20200109161911-78a77eb717b4
$(STYX): .bingo/styx.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/styx-v0.0.0-20200109161911-78a77eb717b4"
	@cd .bingo && $(GO) build -modfile=styx.mod -o=$(GOBIN)/styx-v0.0.0-20200109161911-78a77eb717b4 "github.com/go-pluto/styx"

UP := $(GOBIN)/up-v0.0.0-20200928171403-120d85735d11
$(UP): .bingo/up.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/up-v0.0.0-20200928171403-120d85735d11"
	@cd .bingo && $(GO) build -modfile=up.mod -o=$(GOBIN)/up-v0.0.0-20200928171403-120d85735d11 "github.com/observatorium/up/cmd/up"

GUBERNATOR := $(GOBIN)/gubernator-v1.0.0-rc.3
$(GUBERNATOR): .bingo/gubernator.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/gubernator-v1.0.0-rc.3"
	@cd .bingo && $(GO) build -modfile=gubernator.mod -o=$(GOBIN)/gubernator-v1.0.0-rc.3 "github.com/mailgun/gubernator/cmd/gubernator"

PROTOC_GEN_GO := $(GOBIN)/protoc-gen-go-v1.4.2
$(PROTOC_GEN_GO): .bingo/protoc-gen-go.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/protoc-gen-go-v1.4.2"
	@cd .bingo && $(GO) build -modfile=protoc-gen-go.mod -o=$(GOBIN)/protoc-gen-go-v1.4.2 "github.com/golang/protobuf/protoc-gen-go"

