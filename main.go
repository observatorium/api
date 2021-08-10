package main

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	rbacproxytls "github.com/brancz/kube-rbac-proxy/pkg/tls"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/metalmatze/signal/healthcheck"
	"github.com/metalmatze/signal/internalserver"
	"github.com/observatorium/api/logger"
	"github.com/observatorium/api/server"
	"github.com/observatorium/api/tenants"
	"github.com/observatorium/api/tls"
	"github.com/observatorium/api/tracing"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/version"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.uber.org/automaxprocs/maxprocs"
)

const (
	readTimeout  = 15 * time.Minute
	writeTimeout = 2 * time.Minute
	gracePeriod  = 1 * time.Second
	middlewareTimeout
)

type config struct {
	logLevel          string
	logFormat         string
	rbacConfigPath    string
	tenantsConfigPath string
	metrics           tenants.MetricsConfig
	logs              tenants.LogsConfig
	debug             debugConfig
	server            serverConfig
	tls               tlsConfig
	middleware        middlewareConfig
	internalTracing   internalTracingConfig
}

type debugConfig struct {
	MutexProfileFraction int
	BlockProfileRate     int
	Name                 string
}

type serverConfig struct {
	Listen         string
	ListenInternal string
	HealthcheckURL string
}

type tlsConfig struct {
	MinVersion     string
	CipherSuites   []string
	ReloadInterval time.Duration

	ServerCertFile string
	ServerKeyFile  string

	HealthchecksServerCAFile string
	HealthchecksServerName   string
}

type middlewareConfig struct {
	RateLimiterAddress                string
	ConcurrentRequestLimit            int
	BackLogLimitConcurrentRequests    int
	BackLogDurationConcurrentRequests time.Duration
}

type internalTracingConfig struct {
	ServiceName      string
	Endpoint         string
	EndpointType     tracing.EndpointType
	SamplingFraction float64
}

//nolint:funlen
func main() {
	cfg, err := parseFlags()
	if err != nil {
		stdlog.Fatalf("parse flag: %v", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		version.NewCollector("observatorium"),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	logger := logger.NewLogger(cfg.logLevel, cfg.logFormat, cfg.debug.Name)
	defer level.Info(logger).Log("msg", "exiting")

	tp, closer, err := tracing.InitTracer(
		cfg.internalTracing.ServiceName,
		cfg.internalTracing.Endpoint,
		cfg.internalTracing.EndpointType,
		cfg.internalTracing.SamplingFraction,
	)
	defer closer()

	if err != nil {
		level.Error(logger).Log("msg", "initialize tracer:", "err", err)
		return
	}

	otel.SetErrorHandler(otelErrorHandler{logger: logger})

	debug := os.Getenv("DEBUG") != ""
	if debug {
		runtime.SetMutexProfileFraction(cfg.debug.MutexProfileFraction)
		runtime.SetBlockProfileRate(cfg.debug.BlockProfileRate)
	}
	// maxprocs will automate adjustment by using cgroups info about cpu limit if it set as value for runtime.GOMAXPROCS.
	undo, err := maxprocs.Set(maxprocs.Logger(func(template string, args ...interface{}) {}))
	if err != nil {
		level.Error(logger).Log("msg", "failed to set GOMAXPROCS:", "err", err)
	}

	defer undo()

	var g run.Group
	{
		sig := make(chan os.Signal, 1)
		g.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			level.Info(logger).Log("msg", "caught interrupt")
			return nil
		}, func(_ error) {
			close(sig)
		})
	}
	{
		r := chi.NewRouter()
		commonMiddlewares(r, &cfg, logger)
		tenants.Register(
			r,
			cfg.tenantsConfigPath,
			cfg.rbacConfigPath,
			cfg.middleware.RateLimiterAddress,
			cfg.metrics,
			cfg.logs,
			logger,
			reg,
		)

		tlsConfig, err := tls.NewServerConfig(
			log.With(logger, "protocol", "HTTP"),
			cfg.tls.ServerCertFile,
			cfg.tls.ServerKeyFile,
			cfg.tls.MinVersion,
			cfg.tls.CipherSuites,
		)
		if err != nil {
			level.Error(logger).Log("msg", "failed to initialize tls config:", "err", err)
			return
		}
		if tlsConfig != nil {
			r, err := rbacproxytls.NewCertReloader(
				cfg.tls.ServerCertFile,
				cfg.tls.ServerKeyFile,
				cfg.tls.ReloadInterval,
			)
			if err != nil {
				level.Error(logger).Log("msg", "failed to initialize certificate reloader:", "err", err)
				return
			}
			tlsConfig.GetCertificate = r.GetCertificate
			ctx, cancel := context.WithCancel(context.Background())
			g.Add(func() error {
				return r.Watch(ctx)
			}, func(error) {
				cancel()
			})
		}

		s := http.Server{
			Addr:         cfg.server.Listen,
			Handler:      otelhttp.NewHandler(r, "api", otelhttp.WithTracerProvider(tp)),
			TLSConfig:    tlsConfig,
			ReadTimeout:  readTimeout,  // best set per handler.
			WriteTimeout: writeTimeout, // best set per handler.
		}
		g.Add(func() error {
			level.Info(logger).Log("msg", "starting the HTTP server", "address", cfg.server.Listen)
			if tlsConfig != nil {
				return s.ListenAndServeTLS("", "")
			}

			return s.ListenAndServe()
		}, func(err error) {
			// gracePeriod is duration the server gracefully shuts down.
			ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
			defer cancel()
			level.Info(logger).Log("msg", "shutting down the HTTP server")
			_ = s.Shutdown(ctx)
		})
	}
	{
		healthchecks := commonHealthChecks(&cfg, reg)
		s := setupInternalServer(&cfg, reg, *healthchecks)
		g.Add(func() error {
			level.Info(logger).Log("msg", "starting internal HTTP server", "address", s.Addr)
			return s.ListenAndServe()
		}, func(err error) {
			_ = s.Shutdown(context.Background())
		})
	}

	if err := g.Run(); err != nil {
		return
	}
}

//nolint:funlen
func parseFlags() (config, error) {
	var (
		rawTLSCipherSuites      string
		rawMetricsReadEndpoint  string
		rawMetricsWriteEndpoint string
		rawLogsReadEndpoint     string
		rawLogsTailEndpoint     string
		rawLogsWriteEndpoint    string
		rawTracingEndpointType  string
	)

	cfg := config{}

	flag.StringVar(&cfg.rbacConfigPath, "rbac.config", "rbac.yaml",
		"Path to the RBAC configuration file.")
	flag.StringVar(&cfg.tenantsConfigPath, "tenants.config", "tenants.yaml",
		"Path to the tenants file.")
	flag.StringVar(&cfg.debug.Name, "debug.name", "observatorium",
		"A name to add as a prefix to log lines.")
	flag.IntVar(&cfg.debug.MutexProfileFraction, "debug.mutex-profile-fraction", 10,
		"The percentage of mutex contention events that are reported in the mutex profile.")
	flag.IntVar(&cfg.debug.BlockProfileRate, "debug.block-profile-rate", 10,
		"The percentage of goroutine blocking events that are reported in the blocking profile.")
	flag.StringVar(&cfg.logLevel, "log.level", "info",
		"The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&cfg.logFormat, "log.format", logger.LogFormatLogfmt,
		"The log format to use. Options: 'logfmt', 'json'.")
	flag.StringVar(&cfg.internalTracing.ServiceName, "internal.tracing.service-name", "observatorium_api",
		"The service name to report to the tracing backend.")
	flag.StringVar(&cfg.internalTracing.Endpoint, "internal.tracing.endpoint", "",
		"The full URL of the trace agent or collector. If it's not set, tracing will be disabled.")
	flag.StringVar(&rawTracingEndpointType, "internal.tracing.endpoint-type", string(tracing.EndpointTypeAgent),
		fmt.Sprintf("The tracing endpoint type. Options: '%s', '%s'.", tracing.EndpointTypeAgent, tracing.EndpointTypeCollector))
	flag.Float64Var(&cfg.internalTracing.SamplingFraction, "internal.tracing.sampling-fraction", 0.1,
		"The fraction of traces to sample. Thus, if you set this to .5, half of traces will be sampled.")
	flag.StringVar(&cfg.server.Listen, "web.listen", ":8080",
		"The address on which the public server listens.")
	flag.StringVar(&cfg.server.ListenInternal, "web.internal.listen", ":8081",
		"The address on which the internal server listens.")
	flag.StringVar(&cfg.server.HealthcheckURL, "web.healthchecks.url", "http://localhost:8080",
		"The URL against which to run healthchecks.")
	flag.StringVar(&rawLogsTailEndpoint, "logs.tail.endpoint", "",
		"The endpoint against which to make tail read requests for logs.")
	flag.StringVar(&rawLogsReadEndpoint, "logs.read.endpoint", "",
		"The endpoint against which to make read requests for logs.")
	flag.StringVar(&cfg.logs.TenantHeader, "logs.tenant-header", "X-Scope-OrgID",
		"The name of the HTTP header containing the tenant ID to forward to the logs upstream.")
	flag.StringVar(&rawLogsWriteEndpoint, "logs.write.endpoint", "",
		"The endpoint against which to make write requests for logs.")
	flag.StringVar(&rawMetricsReadEndpoint, "metrics.read.endpoint", "",
		"The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.")
	flag.StringVar(&rawMetricsWriteEndpoint, "metrics.write.endpoint", "",
		"The endpoint against which to make write requests for metrics.")
	flag.StringVar(&cfg.metrics.TenantHeader, "metrics.tenant-header", "THANOS-TENANT",
		"The name of the HTTP header containing the tenant ID to forward to the metrics upstreams.")
	flag.StringVar(&cfg.metrics.TenantLabel, "metrics.tenant-label", "tenant_id",
		"The name of the PromQL label that should hold the tenant ID in metrics upstreams.")
	flag.StringVar(&cfg.tls.ServerCertFile, "tls.server.cert-file", "",
		"File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.ServerKeyFile, "tls.server.key-file", "",
		"File containing the default x509 private key matching --tls.server.cert-file. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.HealthchecksServerCAFile, "tls.healthchecks.server-ca-file", "",
		"File containing the TLS CA against which to verify servers."+
			" If no server CA is specified, the client will use the system certificates.")
	flag.StringVar(&cfg.tls.HealthchecksServerName, "tls.healthchecks.server-name", "",
		"Server name is used to verify the hostname of the certificates returned by the server."+
			" If no server name is specified, the server name will be inferred from the healthcheck URL.")
	flag.StringVar(&cfg.tls.MinVersion, "tls.min-version", "VersionTLS13",
		"Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flag.StringVar(&rawTLSCipherSuites, "tls.cipher-suites", "",
		"Comma-separated list of cipher suites for the server."+
			" Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants)."+
			" If omitted, the default Go cipher suites will be used."+
			" Note that TLS 1.3 ciphersuites are not configurable.")
	flag.DurationVar(&cfg.tls.ReloadInterval, "tls.reload-interval", time.Minute,
		"The interval at which to watch for TLS certificate changes.")
	flag.StringVar(&cfg.middleware.RateLimiterAddress, "middleware.rate-limiter.grpc-address", "",
		"The gRPC Server Address against which to run rate limit checks when the rate limits are specified for a given tenant."+
			" If not specified, local, non-shared rate limiting will be used.")
	flag.IntVar(&cfg.middleware.ConcurrentRequestLimit, "middleware.concurrent-request-limit", 10_000,
		"The limit that controls the number of concurrently processed requests across all tenants.")
	flag.IntVar(&cfg.middleware.BackLogLimitConcurrentRequests, "middleware.backlog-limit-concurrent-requests", 0,
		"The number of concurrent requests that can buffered.")
	flag.DurationVar(&cfg.middleware.BackLogDurationConcurrentRequests, "middleware.backlog-duration-concurrent-requests", 1*time.Millisecond,
		"The time duration to buffer up concurrent requests.")

	flag.Parse()

	metricsReadEndpoint, err := url.ParseRequestURI(rawMetricsReadEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.read.endpoint %q is invalid: %w", rawMetricsReadEndpoint, err)
	}

	cfg.metrics.ReadEndpoint = metricsReadEndpoint

	metricsWriteEndpoint, err := url.ParseRequestURI(rawMetricsWriteEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.write.endpoint %q is invalid: %w", rawMetricsWriteEndpoint, err)
	}

	cfg.metrics.WriteEndpoint = metricsWriteEndpoint

	if rawLogsReadEndpoint != "" {
		cfg.logs.Enabled = true

		logsReadEndpoint, err := url.ParseRequestURI(rawLogsReadEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.read.endpoint is invalid, raw %s: %w", rawLogsReadEndpoint, err)
		}

		cfg.logs.ReadEndpoint = logsReadEndpoint
	}

	if rawLogsTailEndpoint != "" {
		cfg.logs.Enabled = true

		logsTailEndpoint, err := url.ParseRequestURI(rawLogsTailEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.tail.endpoint is invalid, raw %s: %w", rawLogsTailEndpoint, err)
		}

		cfg.logs.TailEndpoint = logsTailEndpoint
	}

	if rawLogsWriteEndpoint != "" {
		cfg.logs.Enabled = true

		logsWriteEndpoint, err := url.ParseRequestURI(rawLogsWriteEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.write.endpoint is invalid, raw %s: %w", rawLogsWriteEndpoint, err)
		}

		cfg.logs.WriteEndpoint = logsWriteEndpoint
	}

	if rawTLSCipherSuites != "" {
		cfg.tls.CipherSuites = strings.Split(rawTLSCipherSuites, ",")
	}

	cfg.internalTracing.EndpointType = tracing.EndpointType(rawTracingEndpointType)

	return cfg, nil
}

// Apply common middlewares across all the tenants.
func commonMiddlewares(r *chi.Mux, cfg *config, logger log.Logger) {
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(middlewareTimeout)) // best set per handler.
	// With default value of zero backlog concurrent requests crossing a rate-limit result in non-200 HTTP response.
	r.Use(middleware.ThrottleBacklog(cfg.middleware.ConcurrentRequestLimit,
		cfg.middleware.BackLogLimitConcurrentRequests, cfg.middleware.BackLogDurationConcurrentRequests))
	r.Use(server.Logger(logger))
}

// commonHealthChecks returns handler for common healthchecks across all the tenants.
func commonHealthChecks(cfg *config, reg prometheus.Registerer) *healthcheck.Handler {
	healthchecks := healthcheck.NewMetricsHandler(healthcheck.NewHandler(), reg)

	if cfg.server.HealthcheckURL != "" {
		t := (http.DefaultTransport).(*http.Transport).Clone()
		t.TLSClientConfig = &stdtls.Config{
			ServerName: cfg.tls.HealthchecksServerName,
		}

		if cfg.tls.HealthchecksServerCAFile != "" {
			caCert, err := ioutil.ReadFile(cfg.tls.HealthchecksServerCAFile)
			if err != nil {
				stdlog.Fatalf("failed to initialize healthcheck server TLS CA: %v", err)
			}

			t.TLSClientConfig.RootCAs = x509.NewCertPool()
			t.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert)
		}

		// Checks if server is up.
		healthchecks.AddLivenessCheck("http",
			healthcheck.HTTPCheckClient(
				&http.Client{Transport: t},
				cfg.server.HealthcheckURL,
				http.MethodGet,
				http.StatusNotFound,
				time.Second,
			),
		)
	}

	return &healthchecks
}

// Create internal server.
func setupInternalServer(cfg *config, reg *prometheus.Registry, healthchecks healthcheck.Handler) *http.Server {
	h := internalserver.NewHandler(
		internalserver.WithName("Internal - Observatorium API"),
		internalserver.WithHealthchecks(healthchecks),
		internalserver.WithPrometheusRegistry(reg),
		internalserver.WithPProf(),
	)

	s := http.Server{
		Addr:    cfg.server.ListenInternal,
		Handler: h,
	}

	return &s
}

type otelErrorHandler struct {
	logger log.Logger
}

func (oh otelErrorHandler) Handle(err error) {
	level.Error(oh.logger).Log("msg", "opentelemetry", "err", err.Error())
}
