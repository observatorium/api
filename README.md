# observatorium

[![semver](https://img.shields.io/badge/semver--0.0.0-blue.svg?cacheSeconds=2592000)](https://github.com/observatorium/observatorium/releases) [![Maintenance](https://img.shields.io/maintenance/yes/2019.svg)](https://github.com/observatorium/observatorium/commits/master) [![Build Status](https://cloud.drone.io/api/badges/observatorium/observatorium/status.svg)](https://cloud.drone.io/observatorium/observatorium) [![Go Doc](https://godoc.org/github.com/observatorium/observatorium?status.svg)](http://godoc.org/github.com/observatorium/observatorium) [![Go Report Card](https://goreportcard.com/badge/github.com/observatorium/observatorium)](https://goreportcard.com/report/github.com/observatorium/observatorium)

Observatorium API

## Usage

[embedmd]:# (tmp/help.txt)
```txt
Usage of ./observatorium:
  -debug.name string
    	The Name to add as prefix to log lines. (default "observatorium")
  -grace-period string
    	The time to wait after an OS interrupt received. (default "5s")
  -listen string
    	The address on which internal server runs. (default ":8080")
  -log.format string
    	The log format to use. Options: 'logfmt', 'json'. (default "logfmt")
  -log.level string
    	The log filtering level. Options: 'error', 'warn', 'info', 'debug'. (default "info")
  -metrics-read-endpoint string
    	The endpoint to which to make write requests for metrics.
  -metrics-write-endpoint string
    	The endpoint to which to make read requests for metrics.
```
