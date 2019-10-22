# observatorium

[![semver](https://img.shields.io/badge/semver--0.0.0-blue.svg?cacheSeconds=2592000)](https://github.com/observatorium/observatorium/releases) [![Maintenance](https://img.shields.io/maintenance/yes/2019.svg)](https://github.com/observatorium/observatorium/commits/master) [![CircleCI](https://circleci.com/gh/observatorium/observatorium.svg?style=svg)](https://circleci.com/gh/observatorium/observatorium)[![Go Doc](https://godoc.org/github.com/observatorium/observatorium?status.svg)](http://godoc.org/github.com/observatorium/observatorium) [![Go Report Card](https://goreportcard.com/badge/github.com/observatorium/observatorium)](https://goreportcard.com/report/github.com/observatorium/observatorium)

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
  -grace-period string
    	The time to wait after an OS interrupt received. (default "5s")
  -listen string
    	The address on which internal server runs. (default ":8080")
  -log.format string
    	The log format to use. Options: 'logfmt', 'json'. (default "logfmt")
  -log.level string
    	The log filtering level. Options: 'error', 'warn', 'info', 'debug'. (default "info")
  -metrics.query.endpoint string
    	The endpoint against which to query for metrics.
  -metrics.write.endpoint string
    	The endpoint against which to make write requests for metrics.
  -proxy.buffer-count int
    	Maximum number of of reusable buffer used for copying HTTP reverse proxy responses. (default 2048)
  -proxy.buffer-size-bytes int
    	Size (bytes) of reusable buffer used for copying HTTP reverse proxy responses. (default 32768)
```
