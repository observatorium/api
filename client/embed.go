package client

import (
	_ "embed"
)

// OpenAPISpecification is the Observatorium's OpenAPI specificiation in YAML format.
//
//go:embed spec.yaml
var OpenAPISpecification []byte
