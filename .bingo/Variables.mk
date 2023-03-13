# Auto generated binary variables helper managed by https://github.com/bwplotka/bingo v0.8. DO NOT EDIT.
# All tools are designed to be build inside $GOBIN.
BINGO_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
GOPATH ?= $(shell go env GOPATH)
GOBIN  ?= $(firstword $(subst :, ,${GOPATH}))/bin
GO     ?= $(shell which go)

# Below generated variables ensure that every time a tool under each variable is invoked, the correct version
# will be used; reinstalling only if needed.
# For example for bingo variable:
#
# In your main Makefile (for non array binaries):
#
#include .bingo/Variables.mk # Assuming -dir was set to .bingo .
#
#command: $(BINGO)
#	@echo "Running bingo"
#	@$(BINGO) <flags/args..>
#
BINGO := $(GOBIN)/bingo-v0.7.0
$(BINGO): $(BINGO_DIR)/bingo.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/bingo-v0.7.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=bingo.mod -o=$(GOBIN)/bingo-v0.7.0 "github.com/bwplotka/bingo"

DEX := $(GOBIN)/dex-v0.0.0-20200512115545-709d4169d646
$(DEX): $(BINGO_DIR)/dex.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/dex-v0.0.0-20200512115545-709d4169d646"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=dex.mod -o=$(GOBIN)/dex-v0.0.0-20200512115545-709d4169d646 "github.com/dexidp/dex/cmd/dex"

EMBEDMD := $(GOBIN)/embedmd-v1.0.0
$(EMBEDMD): $(BINGO_DIR)/embedmd.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/embedmd-v1.0.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=embedmd.mod -o=$(GOBIN)/embedmd-v1.0.0 "github.com/campoy/embedmd"

FAILLINT := $(GOBIN)/faillint-v1.11.0
$(FAILLINT): $(BINGO_DIR)/faillint.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/faillint-v1.11.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=faillint.mod -o=$(GOBIN)/faillint-v1.11.0 "github.com/fatih/faillint"

GOIMPORTS := $(GOBIN)/goimports-v0.4.0
$(GOIMPORTS): $(BINGO_DIR)/goimports.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/goimports-v0.4.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=goimports.mod -o=$(GOBIN)/goimports-v0.4.0 "golang.org/x/tools/cmd/goimports"

GOJSONTOYAML := $(GOBIN)/gojsontoyaml-v0.0.0-20200602132005-3697ded27e8c
$(GOJSONTOYAML): $(BINGO_DIR)/gojsontoyaml.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/gojsontoyaml-v0.0.0-20200602132005-3697ded27e8c"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=gojsontoyaml.mod -o=$(GOBIN)/gojsontoyaml-v0.0.0-20200602132005-3697ded27e8c "github.com/brancz/gojsontoyaml"

GOLANGCI_LINT := $(GOBIN)/golangci-lint-v1.51.2
$(GOLANGCI_LINT): $(BINGO_DIR)/golangci-lint.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/golangci-lint-v1.51.2"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=golangci-lint.mod -o=$(GOBIN)/golangci-lint-v1.51.2 "github.com/golangci/golangci-lint/cmd/golangci-lint"

GOYACC := $(GOBIN)/goyacc-v0.1.5
$(GOYACC): $(BINGO_DIR)/goyacc.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/goyacc-v0.1.5"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=goyacc.mod -o=$(GOBIN)/goyacc-v0.1.5 "golang.org/x/tools/cmd/goyacc"

GUBERNATOR := $(GOBIN)/gubernator-v1.0.0-rc.3
$(GUBERNATOR): $(BINGO_DIR)/gubernator.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/gubernator-v1.0.0-rc.3"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=gubernator.mod -o=$(GOBIN)/gubernator-v1.0.0-rc.3 "github.com/mailgun/gubernator/cmd/gubernator"

JB := $(GOBIN)/jb-v0.4.0
$(JB): $(BINGO_DIR)/jb.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/jb-v0.4.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=jb.mod -o=$(GOBIN)/jb-v0.4.0 "github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb"

JSONNET := $(GOBIN)/jsonnet-v0.16.0
$(JSONNET): $(BINGO_DIR)/jsonnet.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/jsonnet-v0.16.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=jsonnet.mod -o=$(GOBIN)/jsonnet-v0.16.0 "github.com/google/go-jsonnet/cmd/jsonnet"

JSONNETFMT := $(GOBIN)/jsonnetfmt-v0.16.0
$(JSONNETFMT): $(BINGO_DIR)/jsonnetfmt.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/jsonnetfmt-v0.16.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=jsonnetfmt.mod -o=$(GOBIN)/jsonnetfmt-v0.16.0 "github.com/google/go-jsonnet/cmd/jsonnetfmt"

KUBEVAL := $(GOBIN)/kubeval-v0.0.0-20201005082916-38668c6c5b23
$(KUBEVAL): $(BINGO_DIR)/kubeval.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/kubeval-v0.0.0-20201005082916-38668c6c5b23"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=kubeval.mod -o=$(GOBIN)/kubeval-v0.0.0-20201005082916-38668c6c5b23 "github.com/instrumenta/kubeval"

MISSPELL := $(GOBIN)/misspell-v0.3.4
$(MISSPELL): $(BINGO_DIR)/misspell.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/misspell-v0.3.4"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=misspell.mod -o=$(GOBIN)/misspell-v0.3.4 "github.com/client9/misspell/cmd/misspell"

OAPI_CODEGEN := $(GOBIN)/oapi-codegen-v1.9.0
$(OAPI_CODEGEN): $(BINGO_DIR)/oapi-codegen.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/oapi-codegen-v1.9.0"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=oapi-codegen.mod -o=$(GOBIN)/oapi-codegen-v1.9.0 "github.com/deepmap/oapi-codegen/cmd/oapi-codegen"

OPA := $(GOBIN)/opa-v0.23.2
$(OPA): $(BINGO_DIR)/opa.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/opa-v0.23.2"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=opa.mod -o=$(GOBIN)/opa-v0.23.2 "github.com/open-policy-agent/opa"

PROTOC_GEN_GO := $(GOBIN)/protoc-gen-go-v1.4.2
$(PROTOC_GEN_GO): $(BINGO_DIR)/protoc-gen-go.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/protoc-gen-go-v1.4.2"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=protoc-gen-go.mod -o=$(GOBIN)/protoc-gen-go-v1.4.2 "github.com/golang/protobuf/protoc-gen-go"

STYX := $(GOBIN)/styx-v0.0.0-20200109161911-78a77eb717b4
$(STYX): $(BINGO_DIR)/styx.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/styx-v0.0.0-20200109161911-78a77eb717b4"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=styx.mod -o=$(GOBIN)/styx-v0.0.0-20200109161911-78a77eb717b4 "github.com/go-pluto/styx"

UP := $(GOBIN)/up-v0.0.0-20200928171403-120d85735d11
$(UP): $(BINGO_DIR)/up.mod
	@# Install binary/ries using Go 1.14+ build command. This is using bwplotka/bingo-controlled, separate go module with pinned dependencies.
	@echo "(re)installing $(GOBIN)/up-v0.0.0-20200928171403-120d85735d11"
	@cd $(BINGO_DIR) && GOWORK=off $(GO) build -mod=mod -modfile=up.mod -o=$(GOBIN)/up-v0.0.0-20200928171403-120d85735d11 "github.com/observatorium/up/cmd/up"

