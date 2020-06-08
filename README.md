# observatorium

[![CircleCI](https://circleci.com/gh/observatorium/observatorium.svg?style=svg)](https://circleci.com/gh/observatorium/observatorium)
[![Go Doc](https://godoc.org/github.com/observatorium/observatorium?status.svg)](http://godoc.org/github.com/observatorium/observatorium)
[![Go Report Card](https://goreportcard.com/badge/github.com/observatorium/observatorium)](https://goreportcard.com/report/github.com/observatorium/observatorium)

Observatorium API

## Usage

[embedmd]:# (tmp/help.txt)
```txt
Usage of ./observatorium:
  -debug.block-profile-rate int
    	The percentage of goroutine blocking events that are reported in the blocking profile. (default 10)
  -debug.mutex-profile-fraction int
    	The percentage of mutex contention events that are reported in the mutex profile. (default 10)
  -debug.name string
    	A name to add as a prefix to log lines. (default "observatorium")
  -log.format string
    	The log format to use. Options: 'logfmt', 'json'. (default "logfmt")
  -log.level string
    	The log filtering level. Options: 'error', 'warn', 'info', 'debug'. (default "info")
  -logs.read.endpoint string
    	The endpoint against which to make read requests for logs.
  -logs.tenant-header string
    	The name of the HTTP header containing the tenant ID to forward to the logs upstream. (default "X-Scope-OrgID")
  -logs.write.endpoint string
    	The endpoint against which to make write requests for logs.
  -metrics.read.endpoint string
    	The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.
  -metrics.tenant-header string
    	The name of the HTTP header containing the tenant ID to forward to the metrics upstreams. (default "THANOS-TENANT")
  -metrics.write.endpoint string
    	The endpoint against which to make write requests for metrics.
  -rbac.config string
    	Path to the RBAC configuration file. (default "rbac.yaml")
  -tenants.config string
    	Path to the tenants file. (default "tenants.yaml")
  -tls-cert-file string
    	File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.
  -tls-cipher-suites string
    	Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).If omitted, the default Go cipher suites will be used.Note that TLS 1.3 ciphersuites are not configurable.
  -tls-client-ca-file string
    	File containing the TLS CA against which to verify clients.If no client CA is specified, there won't be any client verification on server side.
  -tls-min-version string
    	Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants. (default "VersionTLS13")
  -tls-private-key-file string
    	File containing the default x509 private key matching --tls-cert-file. Leave blank to disable TLS.
  -tls-reload-interval duration
    	The interval at which to watch for TLS certificate changes. (default 1m0s)
  -web.healthchecks.url string
    	The URL against which to run healthchecks. (default "http://localhost:8080")
  -web.internal.listen string
    	The address on which the internal server listens. (default ":8081")
  -web.listen string
    	The address on which the public server listens. (default ":8080")
```
