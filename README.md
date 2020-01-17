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
  -metrics.read.disable
    	The flag to disable handling read requests.
  -metrics.read.endpoint string
    	The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.
  -metrics.ui.endpoint string
    	The endpoint which forward ui requests.
  -metrics.write.disable
    	The flag to disable handling write requests.
  -metrics.write.endpoint string
    	The endpoint against which to make write requests for metrics.
  -proxy.buffer-count int
    	Maximum number of of reusable buffer used for copying HTTP reverse proxy responses. (default 2048)
  -proxy.buffer-size-bytes int
    	Size (bytes) of reusable buffer used for copying HTTP reverse proxy responses. (default 32768)
  -proxy.flush-interval duration
    	The flush interval to flush to the proxy while copying the response body. If zero, no periodic flushing is done. A negative value means to flush immediately after each write to the client. (default -1ns)
  -web.grace-period duration
    	The time to wait after an OS interrupt received. (default 5s)
  -web.listen string
    	The address on which internal server runs. (default ":8080")
  -web.timeout duration
    	The maximum duration before timing out the request, and closing idle connections. (default 5m0s)
```
