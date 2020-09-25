// +build tools

package main

import (
	_ "github.com/brancz/gojsontoyaml"
	_ "github.com/campoy/embedmd"
	_ "github.com/dexidp/dex/cmd/dex"
	_ "github.com/go-pluto/styx"
	_ "github.com/google/go-jsonnet/cmd/jsonnet"
	_ "github.com/google/go-jsonnet/cmd/jsonnetfmt"
	_ "github.com/instrumenta/kubeval"
	_ "github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb"
	_ "github.com/observatorium/up/cmd/up"
	_ "github.com/open-policy-agent/opa"
)
