package main

import (
	"flag"
	"fmt"
	stdlog "log"
	"net/url"
	"strings"
	"time"

	"github.com/observatorium/api/logger"
	"github.com/observatorium/api/tenants"
	"github.com/observatorium/api/tracing"
)

func main() {
	cfg, err := parseFlags()
	if err != nil {
		stdlog.Fatalf("parse flag: %v", err)
	}

	tenants.Run(&cfg)
}

//nolint:funlen
func parseFlags() (tenants.Config, error) {
	var (
		rawTLSCipherSuites      string
		rawMetricsReadEndpoint  string
		rawMetricsWriteEndpoint string
		rawLogsReadEndpoint     string
		rawLogsTailEndpoint     string
		rawLogsWriteEndpoint    string
		rawTracingEndpointType  string
	)

	cfg := tenants.Config{}

	flag.StringVar(&cfg.RBACConfigPath, "rbac.config", "rbac.yaml",
		"Path to the RBAC configuration file.")
	flag.StringVar(&cfg.TenantsConfigPath, "tenants.config", "tenants.yaml",
		"Path to the tenants file.")
	flag.StringVar(&cfg.Debug.Name, "debug.name", "observatorium",
		"A name to add as a prefix to log lines.")
	flag.IntVar(&cfg.Debug.MutexProfileFraction, "debug.mutex-profile-fraction", 10,
		"The percentage of mutex contention events that are reported in the mutex profile.")
	flag.IntVar(&cfg.Debug.BlockProfileRate, "debug.block-profile-rate", 10,
		"The percentage of goroutine blocking events that are reported in the blocking profile.")
	flag.StringVar(&cfg.LogLevel, "log.level", "info",
		"The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&cfg.LogFormat, "log.format", logger.LogFormatLogfmt,
		"The log format to use. Options: 'logfmt', 'json'.")
	flag.StringVar(&cfg.InternalTracing.ServiceName, "internal.tracing.service-name", "observatorium_api",
		"The service name to report to the tracing backend.")
	flag.StringVar(&cfg.InternalTracing.Endpoint, "internal.tracing.endpoint", "",
		"The full URL of the trace agent or collector. If it's not set, tracing will be disabled.")
	flag.StringVar(&rawTracingEndpointType, "internal.tracing.endpoint-type", string(tracing.EndpointTypeAgent),
		fmt.Sprintf("The tracing endpoint type. Options: '%s', '%s'.", tracing.EndpointTypeAgent, tracing.EndpointTypeCollector))
	flag.Float64Var(&cfg.InternalTracing.SamplingFraction, "internal.tracing.sampling-fraction", 0.1,
		"The fraction of traces to sample. Thus, if you set this to .5, half of traces will be sampled.")
	flag.StringVar(&cfg.Server.Listen, "web.listen", ":8080",
		"The address on which the public server listens.")
	flag.StringVar(&cfg.Server.ListenInternal, "web.internal.listen", ":8081",
		"The address on which the internal server listens.")
	flag.StringVar(&cfg.Server.HealthcheckURL, "web.healthchecks.url", "http://localhost:8080",
		"The URL against which to run healthchecks.")
	flag.StringVar(&rawLogsTailEndpoint, "logs.tail.endpoint", "",
		"The endpoint against which to make tail read requests for logs.")
	flag.StringVar(&rawLogsReadEndpoint, "logs.read.endpoint", "",
		"The endpoint against which to make read requests for logs.")
	flag.StringVar(&cfg.Logs.TenantHeader, "logs.tenant-header", "X-Scope-OrgID",
		"The name of the HTTP header containing the tenant ID to forward to the logs upstream.")
	flag.StringVar(&rawLogsWriteEndpoint, "logs.write.endpoint", "",
		"The endpoint against which to make write requests for logs.")
	flag.StringVar(&rawMetricsReadEndpoint, "metrics.read.endpoint", "",
		"The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.")
	flag.StringVar(&rawMetricsWriteEndpoint, "metrics.write.endpoint", "",
		"The endpoint against which to make write requests for metrics.")
	flag.StringVar(&cfg.Metrics.TenantHeader, "metrics.tenant-header", "THANOS-TENANT",
		"The name of the HTTP header containing the tenant ID to forward to the metrics upstreams.")
	flag.StringVar(&cfg.Metrics.TenantLabel, "metrics.tenant-label", "tenant_id",
		"The name of the PromQL label that should hold the tenant ID in metrics upstreams.")
	flag.StringVar(&cfg.TLS.ServerCertFile, "tls.server.cert-file", "",
		"File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.")
	flag.StringVar(&cfg.TLS.ServerKeyFile, "tls.server.key-file", "",
		"File containing the default x509 private key matching --tls.server.cert-file. Leave blank to disable TLS.")
	flag.StringVar(&cfg.TLS.HealthchecksServerCAFile, "tls.healthchecks.server-ca-file", "",
		"File containing the TLS CA against which to verify servers."+
			" If no server CA is specified, the client will use the system certificates.")
	flag.StringVar(&cfg.TLS.HealthchecksServerName, "tls.healthchecks.server-name", "",
		"Server name is used to verify the hostname of the certificates returned by the server."+
			" If no server name is specified, the server name will be inferred from the healthcheck URL.")
	flag.StringVar(&cfg.TLS.MinVersion, "tls.min-version", "VersionTLS13",
		"Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flag.StringVar(&rawTLSCipherSuites, "tls.cipher-suites", "",
		"Comma-separated list of cipher suites for the server."+
			" Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants)."+
			" If omitted, the default Go cipher suites will be used."+
			" Note that TLS 1.3 ciphersuites are not configurable.")
	flag.DurationVar(&cfg.TLS.ReloadInterval, "tls.reload-interval", time.Minute,
		"The interval at which to watch for TLS certificate changes.")
	flag.StringVar(&cfg.Middleware.RateLimiterAddress, "middleware.rate-limiter.grpc-address", "",
		"The gRPC Server Address against which to run rate limit checks when the rate limits are specified for a given tenant."+
			" If not specified, local, non-shared rate limiting will be used.")
	flag.IntVar(&cfg.Middleware.ConcurrentRequestLimit, "middleware.concurrent-request-limit", 10_000,
		"The limit that controls the number of concurrently processed requests across all tenants.")
	flag.IntVar(&cfg.Middleware.BackLogLimitConcurrentRequests, "middleware.backlog-limit-concurrent-requests", 0,
		"The number of concurrent requests that can buffered.")
	flag.DurationVar(&cfg.Middleware.BackLogDurationConcurrentRequests, "middleware.backlog-duration-concurrent-requests", 1*time.Millisecond,
		"The time duration to buffer up concurrent requests.")

	flag.Parse()

	metricsReadEndpoint, err := url.ParseRequestURI(rawMetricsReadEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.read.endpoint %q is invalid: %w", rawMetricsReadEndpoint, err)
	}

	cfg.Metrics.ReadEndpoint = metricsReadEndpoint

	metricsWriteEndpoint, err := url.ParseRequestURI(rawMetricsWriteEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.write.endpoint %q is invalid: %w", rawMetricsWriteEndpoint, err)
	}

	cfg.Metrics.WriteEndpoint = metricsWriteEndpoint

	if rawLogsReadEndpoint != "" {
		cfg.Logs.Enabled = true

		logsReadEndpoint, err := url.ParseRequestURI(rawLogsReadEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.read.endpoint is invalid, raw %s: %w", rawLogsReadEndpoint, err)
		}

		cfg.Logs.ReadEndpoint = logsReadEndpoint
	}

	if rawLogsTailEndpoint != "" {
		cfg.Logs.Enabled = true

		logsTailEndpoint, err := url.ParseRequestURI(rawLogsTailEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.tail.endpoint is invalid, raw %s: %w", rawLogsTailEndpoint, err)
		}

		cfg.Logs.TailEndpoint = logsTailEndpoint
	}

	if rawLogsWriteEndpoint != "" {
		cfg.Logs.Enabled = true

		logsWriteEndpoint, err := url.ParseRequestURI(rawLogsWriteEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.write.endpoint is invalid, raw %s: %w", rawLogsWriteEndpoint, err)
		}

		cfg.Logs.WriteEndpoint = logsWriteEndpoint
	}

	if rawTLSCipherSuites != "" {
		cfg.TLS.CipherSuites = strings.Split(rawTLSCipherSuites, ",")
	}

	cfg.InternalTracing.EndpointType = tracing.EndpointType(rawTracingEndpointType)

	return cfg, nil
}
