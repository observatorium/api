# Observatorium

[![CircleCI](https://circleci.com/gh/observatorium/observatorium.svg?style=svg)](https://circleci.com/gh/observatorium/observatorium)
[![Go Doc](https://godoc.org/github.com/observatorium/observatorium?status.svg)](http://godoc.org/github.com/observatorium/observatorium)
[![Go Report Card](https://goreportcard.com/badge/github.com/observatorium/observatorium)](https://goreportcard.com/report/github.com/observatorium/observatorium)

This project is an API server for Observatorium.
The API provides an authenticated and authorized, multi-tenant interface for writing and reading observability signals, i.e. metrics and logs.

## Backends

The Observatorium API server fulfills requests by proxying reads and writes to a backend for each type of observability signal.

### Metrics

The Observatorium API server can serve read and write requests for Prometheus metrics.
In order to handle requests for metrics, a compatible backend must be configured.

#### --metrics.read.endpoint

The backend from which to read metrics can be specified with the `--metrics.read.endpoint` flag.
Compatible backends must implement the Prometheus HTTP API, e.g. Prometheus, Thanos querier, Cortex, etc.

#### --metrics.write.endpoint

The backend to which to write metrics can be specified with the `--metrics.write.endpoint` flag.
Compatible backends must implement the Prometheus remote-write API, e.g. Thanos receiver, Cortex, etc.

### Logs

The Observatorium API server can serve read and write requests for logs.
In order to handle requests for logs, a compatible backend must be configured.

#### --logs.read.endpoint

The backend from which to read logs can be specified with the `--logs.read.endpoint` flag.
Compatible backends must implement the Loki read API, e.g. Loki.

#### --logs.tail.endpoint

The backend from which to tail logs can be specified with the `--logs.tail.endpoint` flag.
Compatible backends must implement the Loki tail API, e.g. Loki.

#### --logs.write.endpoint

The backend to which to write logs can be specified with the `--logs.write.endpoint` flag.
Compatible backends must implement the Loki write API, e.g. Loki.

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
  -logs.tail.endpoint string
    	The endpoint against which to make tail read requests for logs.
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
  -tls.cipher-suites string
    	Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used. Note that TLS 1.3 ciphersuites are not configurable.
  -tls.healthchecks.server-ca-file string
    	File containing the TLS CA against which to verify servers. If no server CA is specified, the client will use the system certificates.
  -tls.healthchecks.server-name string
    	Server name is used to verify the hostname of the certificates returned by the server. If no server name is specified, the server name will be inferred from the healthcheck URL.
  -tls.min-version string
    	Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants. (default "VersionTLS13")
  -tls.reload-interval duration
    	The interval at which to watch for TLS certificate changes. (default 1m0s)
  -tls.server.cert-file string
    	File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.
  -tls.server.key-file string
    	File containing the default x509 private key matching --tls.server.cert-file. Leave blank to disable TLS.
  -web.healthchecks.url string
    	The URL against which to run healthchecks. (default "http://localhost:8080")
  -web.internal.listen string
    	The address on which the internal server listens. (default ":8081")
  -web.listen string
    	The address on which the public server listens. (default ":8080")
```
