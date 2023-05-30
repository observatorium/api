# Observatorium

[![CircleCI](https://circleci.com/gh/observatorium/api.svg?style=svg)](https://circleci.com/gh/observatorium/api)
[![Go Doc](https://godoc.org/github.com/observatorium/api?status.svg)](http://godoc.org/github.com/observatorium/api)
[![Go Report Card](https://goreportcard.com/badge/github.com/observatorium/api)](https://goreportcard.com/report/github.com/observatorium/api)

This project is an API server for Observatorium.
The API provides an authenticated and authorized, multi-tenant interface for writing and reading observability signals, i.e. metrics and logs.

## Getting started

For a quick start, run:

```bash
make test-interactive
```

This command spins up a full setup for Observatorium API with all dependent services. It is intended for short-lived manual testing on your local environment.

It is also possible to run the [test](test/e2e/interactive_test.go) with flags '-v' (to see the output) and '-test.timeout=9999m' to ensure the test is not terminated.

Since this starts all necessary services in a Docker environment, make sure you have [Docker](https://docs.docker.com/get-docker/) installed.

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

#### --metrics.rules.endpoint

The rules backend to where rules can be stored can be specified with the `--metrics.rules.endpoint` flag.

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
Usage of ./observatorium-api:
  -debug.block-profile-rate int
    	The percentage of goroutine blocking events that are reported in the blocking profile. (default 10)
  -debug.mutex-profile-fraction int
    	The percentage of mutex contention events that are reported in the mutex profile. (default 10)
  -debug.name string
    	A name to add as a prefix to log lines. (default "observatorium")
  -experimental.traces.read.endpoint-template string
    	A template replacing --read.traces.endpoint, such as http://jaeger-{tenant}-query:16686
  -grpc.listen string
    	The address on which the public gRPC server listens.
  -internal.tracing.endpoint string
    	The full URL of the trace agent or collector. If it's not set, tracing will be disabled.
  -internal.tracing.endpoint-type string
    	The tracing endpoint type. Options: 'agent', 'collector'. (default "agent")
  -internal.tracing.sampling-fraction float
    	The fraction of traces to sample. Thus, if you set this to .5, half of traces will be sampled. (default 0.1)
  -internal.tracing.service-name string
    	The service name to report to the tracing backend. (default "observatorium_api")
  -log.format string
    	The log format to use. Options: 'logfmt', 'json'. (default "logfmt")
  -log.level string
    	The log filtering level. Options: 'error', 'warn', 'info', 'debug'. (default "info")
  -logs.read.endpoint string
    	The endpoint against which to make read requests for logs.
  -logs.rules.endpoint string
    	The endpoint against which to make rules requests for logs.
  -logs.rules.label-filters string
    	Allow the following filters to be applied to user rules queries per tenant (e.g. tenantA:namespace,severity;tenantB:severity).
  -logs.rules.read-only
    	Allow only read-only rule requests for logs.
  -logs.rules.tenant-label string
    	The name of the rules label that should hold the tenant ID in logs upstreams. (default "tenant_id")
  -logs.tail.endpoint string
    	The endpoint against which to make tail read requests for logs.
  -logs.tenant-header string
    	The name of the HTTP header containing the tenant ID to forward to the logs upstream. (default "X-Scope-OrgID")
  -logs.tls.ca-file string
    	File containing the TLS CA against which to upstream logs servers. Leave blank to disable TLS.
  -logs.tls.cert-file string
    	File containing the TLS client certificates to authenticate against upstream logs servers. Leave blank to disable mTLS.
  -logs.tls.key-file string
    	File containing the TLS client key to authenticate against upstream logs servers. Leave blank to disable mTLS.
  -logs.write-timeout duration
    	The HTTP write timeout for proxied requests to the logs endpoint. (default 10m0s)
  -logs.write.endpoint string
    	The endpoint against which to make write requests for logs.
  -metrics.read.endpoint string
    	The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.
  -metrics.rules.endpoint string
    	The endpoint against which to make get requests for listing recording/alerting rules and put requests for creating/updating recording/alerting rules.
  -metrics.tenant-header string
    	The name of the HTTP header containing the tenant ID to forward to the metrics upstreams. (default "THANOS-TENANT")
  -metrics.tenant-label string
    	The name of the PromQL label that should hold the tenant ID in metrics upstreams. (default "tenant_id")
  -metrics.tls.ca-file string
    	File containing the TLS CA against which to upstream metrics servers. Leave blank to disable TLS.
  -metrics.tls.cert-file string
    	File containing the TLS client certificates to authenticate against upstream logs servers. Leave blank to disable mTLS.
  -metrics.tls.key-file string
    	File containing the TLS client key to authenticate against upstream metrics servers. Leave blank to disable mTLS.
  -metrics.write-timeout duration
    	The HTTP write timeout for proxied requests to the metrics endpoint. (default 2m0s)
  -metrics.write.endpoint string
    	The endpoint against which to make write requests for metrics.
  -middleware.backlog-duration-concurrent-requests duration
    	The time duration to buffer up concurrent requests. (default 1ms)
  -middleware.backlog-limit-concurrent-requests int
    	The number of concurrent requests that can buffered.
  -middleware.concurrent-request-limit int
    	The limit that controls the number of concurrently processed requests across all tenants. (default 10000)
  -middleware.rate-limiter.grpc-address string
    	The gRPC Server Address against which to run rate limit checks when the rate limits are specified for a given tenant. If not specified, local, non-shared rate limiting will be used.
  -rbac.config string
    	Path to the RBAC configuration file. (default "rbac.yaml")
  -server.read-header-timeout duration
    	Global server read header timeout. (default 1s)
  -server.read-timeout duration
    	Global server read timeout. (default 5s)
  -server.write-timeout duration
    	Global server read timeout. (default 12m0s)
  -tenants.config string
    	Path to the tenants file. (default "tenants.yaml")
  -tls.cipher-suites string
    	Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used. Note that TLS 1.3 ciphersuites are not configurable.
  -tls.client-auth-type string
    	Policy for TLS client-side authentication. Values are from ClientAuthType constants in https://pkg.go.dev/crypto/tls#ClientAuthType (default "RequestClientCert")
  -tls.healthchecks.server-ca-file string
    	File containing the TLS CA against which to verify servers. If no server CA is specified, the client will use the system certificates.
  -tls.healthchecks.server-name string
    	Server name is used to verify the hostname of the certificates returned by the server. If no server name is specified, the server name will be inferred from the healthcheck URL.
  -tls.internal.server.cert-file string
    	File containing the default x509 Certificate for internal HTTPS. Leave blank to disable TLS.
  -tls.internal.server.key-file string
    	File containing the default x509 private key matching --tls.internal.server.cert-file. Leave blank to disable TLS.
  -tls.max-version string
    	Maximum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants. (default "VersionTLS13")
  -tls.min-version string
    	Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants. (default "VersionTLS13")
  -tls.reload-interval duration
    	The interval at which to watch for TLS certificate changes. (default 1m0s)
  -tls.server.cert-file string
    	File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.
  -tls.server.key-file string
    	File containing the default x509 private key matching --tls.server.cert-file. Leave blank to disable TLS.
  -traces.read.endpoint string
    	The endpoint against which to make HTTP read requests for traces.
  -traces.tenant-header string
    	The name of the HTTP header containing the tenant ID to forward to upstream OpenTelemetry collector. (default "X-Tenant")
  -traces.tls.ca-file string
    	File containing the TLS CA against which to upstream traces servers. Leave blank to disable TLS.
  -traces.tls.cert-file string
    	File containing the TLS client certificates to authenticate against upstream logs servers. Leave blank to disable mTLS.
  -traces.tls.key-file string
    	File containing the TLS client key to authenticate against upstream traces servers. Leave blank to disable mTLS.
  -traces.write-timeout duration
    	The HTTP write timeout for proxied requests to the traces endpoint. (default 2m0s)
  -traces.write.endpoint string
    	The endpoint against which to make gRPC write requests for traces.
  -web.healthchecks.url string
    	The URL against which to run healthchecks. (default "http://localhost:8080")
  -web.internal.listen string
    	The address on which the internal server listens. (default ":8081")
  -web.listen string
    	The address on which the public server listens. (default ":8080")
```
