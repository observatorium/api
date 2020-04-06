package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/observatorium/observatorium/internal"
	"github.com/observatorium/observatorium/internal/proxy"
	"github.com/observatorium/observatorium/internal/server"
	"github.com/observatorium/observatorium/internal/tls"

	rbacproxytls "github.com/brancz/kube-rbac-proxy/pkg/tls"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
	"go.uber.org/automaxprocs/maxprocs"
)

type config struct {
	logLevel  string
	logFormat string

	debug   debugConfig
	server  serverConfig
	tls     tlsConfig
	proxy   proxyConfig
	metrics metricsConfig
}

type debugConfig struct {
	mutexProfileFraction int
	blockProfileRate     int
	name                 string
}

type serverConfig struct {
	listen         string
	gracePeriod    time.Duration
	requestTimeout time.Duration
	readTimeout    time.Duration
	writeTimeout   time.Duration
}

type tlsConfig struct {
	certFile       string
	keyFile        string
	clientCAFile   string
	minVersion     string
	cipherSuites   []string
	reloadInterval time.Duration
}

type proxyConfig struct {
	bufferSizeBytes int
	bufferCount     int
	flushInterval   time.Duration
}

type metricsConfig struct {
	uiEndpoint    *url.URL
	readEndpoint  *url.URL
	writeEndpoint *url.URL
}

func main() {
	cfg, err := parseFlags(log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)))
	if err != nil {
		log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr)).Log("msg", "parse flag", "err", err)
		os.Exit(1)
	}

	logger := internal.NewLogger(cfg.logLevel, cfg.logFormat, cfg.debug.name)
	defer level.Info(logger).Log("msg", "exiting")

	debug := os.Getenv("DEBUG") != ""
	if debug {
		runtime.SetMutexProfileFraction(cfg.debug.mutexProfileFraction)
		runtime.SetBlockProfileRate(cfg.debug.blockProfileRate)
	}

	// Running in container with limits but with empty/wrong value of GOMAXPROCS env var could lead to throttling by cpu
	// maxprocs will automate adjustment by using cgroups info about cpu limit if it set as value for runtime.GOMAXPROCS
	undo, err := maxprocs.Set(maxprocs.Logger(func(template string, args ...interface{}) {
		level.Debug(logger).Log("msg", fmt.Sprintf(template, args))
	}))
	if err != nil {
		level.Error(logger).Log("msg", "failed to set GOMAXPROCS:", "err", err)
	}

	defer undo()

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		version.NewCollector("observatorium"),
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	level.Info(logger).Log("msg", "starting observatorium")

	if err := exec(logger, reg, cfg); err != nil {
		level.Error(logger).Log("msg", "observatorium failed", "err", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func exec(logger log.Logger, reg *prometheus.Registry, cfg config) error {
	var g run.Group
	{
		// Signal channels must be buffered.
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

	tlsConfig, err := tls.NewServerConfig(
		log.With(logger, "protocol", "HTTP"),
		cfg.tls.certFile,
		cfg.tls.keyFile,
		cfg.tls.clientCAFile,
		cfg.tls.minVersion,
		cfg.tls.cipherSuites,
	)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	{
		if tlsConfig != nil {
			r, err := rbacproxytls.NewCertReloader(
				cfg.tls.certFile,
				cfg.tls.keyFile,
				cfg.tls.reloadInterval,
			)
			if err != nil {
				return fmt.Errorf("initialize certificate reloader: %w", err)
			}

			tlsConfig.GetCertificate = r.GetCertificate

			ctx, cancel := context.WithCancel(context.Background())
			g.Add(func() error {
				return r.Watch(ctx)
			}, func(error) {
				cancel()
			})
		}
	}
	{
		srv := server.New(
			logger,
			reg,
			server.WithListen(cfg.server.listen),
			server.WithGracePeriod(cfg.server.gracePeriod),
			server.WithRequestTimeout(cfg.server.requestTimeout),
			server.WithReadTimeout(cfg.server.readTimeout),
			server.WithWriteTimeout(cfg.server.writeTimeout),
			server.WithTLSConfig(tlsConfig),
			server.WithProfile(os.Getenv("PROFILE") != ""),
			server.WithMetricUIEndpoint(cfg.metrics.uiEndpoint),
			server.WithMetricReadEndpoint(cfg.metrics.readEndpoint),
			server.WithMetricWriteEndpoint(cfg.metrics.writeEndpoint),
			server.WithProxyOptions(
				proxy.WithBufferCount(cfg.proxy.bufferCount),
				proxy.WithBufferSizeBytes(cfg.proxy.bufferSizeBytes),
				proxy.WithFlushInterval(cfg.proxy.flushInterval),
			),
		)
		g.Add(srv.ListenAndServe, srv.Shutdown)
	}

	return g.Run()
}

func parseFlags(logger log.Logger) (config, error) {
	var (
		rawTLSCipherSuites      string
		rawMetricsUIEndpoint    string
		rawMetricsReadEndpoint  string
		rawMetricsWriteEndpoint string
	)

	cfg := config{}

	flag.StringVar(&cfg.debug.name, "debug.name", "observatorium",
		"The name to add as prefix to log lines.")
	flag.IntVar(&cfg.debug.mutexProfileFraction, "debug.mutex-profile-fraction", 10,
		"The parameter which controls the fraction of mutex contention events that are reported in the mutex profile.")
	flag.IntVar(&cfg.debug.blockProfileRate, "debug.block-profile-rate", 10,
		"The parameter controls the fraction of goroutine blocking events that are reported in the blocking profile.")
	flag.StringVar(&cfg.logLevel, "log.level", "info",
		"The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&cfg.logFormat, "log.format", internal.LogFormatLogfmt,
		"The log format to use. Options: 'logfmt', 'json'.")
	flag.StringVar(&cfg.server.listen, "web.listen", ":8080",
		"The address on which internal server runs.")
	flag.DurationVar(&cfg.server.gracePeriod, "web.grace-period", server.DefaultGracePeriod,
		"The time to wait after an OS interrupt received.")
	flag.DurationVar(&cfg.server.requestTimeout, "web.timeout", server.DefaultRequestTimeout,
		"The maximum duration before timing out the request, and closing idle connections.")
	flag.DurationVar(&cfg.server.readTimeout, "web.timeout.read", server.DefaultReadTimeout,
		"The maximum duration before reading the entire request, including the body.")
	flag.DurationVar(&cfg.server.writeTimeout, "web.timeout.write", server.DefaultWriteTimeout,
		"The maximum duration  before timing out writes of the response.")
	flag.StringVar(&rawMetricsReadEndpoint, "metrics.read.endpoint", "",
		"The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.")
	flag.StringVar(&rawMetricsUIEndpoint, "metrics.ui.endpoint", "",
		"The endpoint which forward ui requests.")
	flag.StringVar(&rawMetricsWriteEndpoint, "metrics.write.endpoint", "",
		"The endpoint against which to make write requests for metrics.")
	flag.IntVar(&cfg.proxy.bufferCount, "proxy.buffer-count", proxy.DefaultBufferCount,
		"Maximum number of of reusable buffer used for copying HTTP reverse proxy responses.")
	flag.IntVar(&cfg.proxy.bufferSizeBytes, "proxy.buffer-size-bytes", proxy.DefaultBufferSizeBytes,
		"Size (bytes) of reusable buffer used for copying HTTP reverse proxy responses.")
	flag.DurationVar(&cfg.proxy.flushInterval, "proxy.flush-interval", proxy.DefaultFlushInterval,
		"The flush interval to flush to the proxy while copying the response body. If zero, no periodic flushing is done. "+
			"A negative value means to flush immediately after each write to the client.")
	flag.StringVar(&cfg.tls.certFile, "tls-cert-file", "",
		"File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.keyFile, "tls-private-key-file", "",
		"File containing the default x509 private key matching --tls-cert-file. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.clientCAFile, "tls-client-ca-file", "",
		"File containing the TLS CA to verify clients against."+
			"If no client CA is specified, there won't be any client verification on server side.")
	flag.StringVar(&cfg.tls.minVersion, "tls-min-version", "VersionTLS13",
		"Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flag.StringVar(&rawTLSCipherSuites, "tls-cipher-suites", "",
		"Comma-separated list of cipher suites for the server."+
			" Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants)."+
			"If omitted, the default Go cipher suites will be used."+
			"Note that TLS 1.3 ciphersuites are not configurable.")
	flag.DurationVar(&cfg.tls.reloadInterval, "tls-reload-interval", time.Minute,
		"The interval at which to watch for TLS certificate changes, by default set to 1 minute.")

	flag.Parse()

	if rawMetricsUIEndpoint != "" {
		metricsUIEndpoint, err := url.ParseRequestURI(rawMetricsUIEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--metrics.ui.endpoint is invalid, raw %s: %w", rawMetricsUIEndpoint, err)
		}

		cfg.metrics.uiEndpoint = metricsUIEndpoint
	} else {
		level.Info(logger).Log("msg", "--metrics.ui.endpoint is not specified, UI will not be accessible")
	}

	metricsReadEndpoint, err := url.ParseRequestURI(rawMetricsReadEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.read.endpoint is invalid, raw %s: %w", rawMetricsReadEndpoint, err)
	}

	cfg.metrics.readEndpoint = metricsReadEndpoint

	metricsWriteEndpoint, err := url.ParseRequestURI(rawMetricsWriteEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.write.endpoint is invalid, raw %s: %w", rawMetricsWriteEndpoint, err)
	}

	cfg.metrics.writeEndpoint = metricsWriteEndpoint

	if rawTLSCipherSuites != "" {
		cfg.tls.cipherSuites = strings.Split(rawTLSCipherSuites, ",")
	}

	return cfg, nil
}
