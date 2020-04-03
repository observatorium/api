# observatorium

[![semver](https://img.shields.io/badge/semver--0.0.0-blue.svg?cacheSeconds=2592000)](https://github.com/observatorium/observatorium/releases) [![Maintenance](https://img.shields.io/maintenance/yes/2020.svg)](https://github.com/observatorium/observatorium/commits/master) [![CircleCI](https://circleci.com/gh/observatorium/observatorium.svg?style=svg)](https://circleci.com/gh/observatorium/observatorium)[![Go Doc](https://godoc.org/github.com/observatorium/observatorium?status.svg)](http://godoc.org/github.com/observatorium/observatorium) [![Go Report Card](https://goreportcard.com/badge/github.com/observatorium/observatorium)](https://goreportcard.com/report/github.com/observatorium/observatorium)[![Docker Repository on Quay](https://quay.io/repository/observatorium/observatorium/status "Docker Repository on Quay")](https://quay.io/repository/observatorium/observatorium)

Observatorium API

## Usage

[embedmd]:# (tmp/help.txt)
```txt
Usage of ./observatorium:
  -debug.block-profile-rate int
    	The parameter controls the fraction of goroutine blocking events that are reported in the blocking profile. (default 10)
  -debug.mutex-profile-fraction int
    	The parameter which controls the fraction of mutex contention events that are reported in the mutex profile. (default 10)
  -debug.name string
    	The name to add as prefix to log lines. (default "observatorium")
  -log.format string
    	The log format to use. Options: 'logfmt', 'json'. (default "logfmt")
  -log.level string
    	The log filtering level. Options: 'error', 'warn', 'info', 'debug'. (default "info")
  -metrics.read.endpoint string
    	The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.
  -metrics.ui.endpoint string
    	The endpoint which forward ui requests.
  -metrics.write.endpoint string
    	The endpoint against which to make write requests for metrics.
  -proxy.buffer-count int
    	Maximum number of of reusable buffer used for copying HTTP reverse proxy responses. (default 2048)
  -proxy.buffer-size-bytes int
    	Size (bytes) of reusable buffer used for copying HTTP reverse proxy responses. (default 32768)
  -proxy.expect-continue-timeout duration
    	The amount of time to wait for a server's first response headers after fully writing the request headers if the request has an "Expect: 100-continue" header.Zero means no timeout and causes the body to be sent immediately, without waiting for the server to approve. (default 1s)
  -proxy.flush-interval duration
    	The flush interval to flush to the proxy while copying the response body. If zero, no periodic flushing is done. A negative value means to flush immediately after each write to the client. (default -1ns)
  -proxy.idle-conn-timeout duration
    	The maximum amount of time an idle (keep-alive) connection will remain idle before closing itself. (default 1m30s)
  -proxy.keep-alive duration
    	The interval between keep-alive probes for an active network connection. (default 30s)
  -proxy.timeout duration
    	the maximum amount of time a dial will wait for a connect to complete. The default is no timeout. (default 30s)
  -proxy.tls-handshake-timeout duration
    	The maximum amount of time waiting to wait for a TLS handshake. Zero means no timeout. (default 10s)
  -tls-cert-file string
    	File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.
  -tls-cipher-suites string
    	Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants).If omitted, the default Go cipher suites will be used.Note that TLS 1.3 ciphersuites are not configurable.
  -tls-client-ca-file string
    	File containing the TLS CA to verify clients against.If no client CA is specified, there won't be any client verification on server side.
  -tls-min-version string
    	Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants. (default "VersionTLS13")
  -tls-private-key-file string
    	File containing the default x509 private key matching --tls-cert-file. Leave blank to disable TLS.
  -tls-reload-interval duration
    	The interval at which to watch for TLS certificate changes, by default set to 1 minute. (default 1m0s)
  -web.grace-period duration
    	The time to wait after an OS interrupt received. (default 5s)
  -web.listen string
    	The address on which internal server runs. (default ":8080")
  -web.timeout duration
    	The maximum duration before timing out the request, and closing idle connections. (default 2m0s)
  -web.timeout.read duration
    	The maximum duration before reading the entire request, including the body. (default 2m0s)
  -web.timeout.write duration
    	The maximum duration  before timing out writes of the response. (default 2m0s)
```
