package main

import (
	"context"
	"flag"
	"fmt"
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
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/observatorium/observatorium/internal"
	metricslegacy "github.com/observatorium/observatorium/internal/api/metrics/legacy"
	metricsv1 "github.com/observatorium/observatorium/internal/api/metrics/v1"
	"github.com/observatorium/observatorium/internal/server"
	"github.com/observatorium/observatorium/internal/tls"
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
	listenInternal string
	healthcheckURL string
	gracePeriod    time.Duration
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
	readEndpoint  *url.URL
	writeEndpoint *url.URL
}

func main() {
	cfg, err := parseFlags(log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)))
	if err != nil {
		stdlog.Fatalf("parse flag: %v", err)
	}

	logger := internal.NewLogger(cfg.logLevel, cfg.logFormat, cfg.debug.name)
	defer level.Info(logger).Log("msg", "exiting")

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		version.NewCollector("observatorium"),
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	healthchecks := healthcheck.NewMetricsHandler(healthcheck.NewHandler(), reg)

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

	level.Info(logger).Log("msg", "starting observatorium")

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
		stdlog.Fatalf("failed to initialize tls config: %v", err)
	}

	{
		if tlsConfig != nil {
			r, err := rbacproxytls.NewCertReloader(
				cfg.tls.certFile,
				cfg.tls.keyFile,
				cfg.tls.reloadInterval,
			)
			if err != nil {
				stdlog.Fatalf("failed to initialize certificate reloader: %v", err)
			}

			tlsConfig.GetCertificate = r.GetCertificate

			ctx, cancel := context.WithCancel(context.Background())
			g.Add(func() error {
				return r.Watch(ctx)
			}, func(error) {
				cancel()
			})
		}

		if cfg.server.healthcheckURL != "" {
			// checks if server is up
			healthchecks.AddLivenessCheck("http",
				healthcheck.HTTPCheck(
					cfg.server.healthcheckURL,
					http.MethodGet,
					http.StatusMovedPermanently,
					time.Second,
				),
			)
			// checks if upstream is reachable through server proxy
			healthchecks.AddReadinessCheck("http-proxy",
				healthcheck.HTTPGetCheck(
					cfg.server.healthcheckURL+"/api/metrics/v1/graph",
					time.Second,
				),
			)
		}

		r := chi.NewRouter()
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Recoverer)
		r.Use(middleware.StripSlashes)
		r.Use(middleware.Timeout(2 * time.Minute)) // best set per handler
		r.Use(server.Logger(logger))

		ins := server.NewInstrumentationMiddleware(reg)

		r.Mount("/",
			metricslegacy.NewHandler(
				cfg.metrics.readEndpoint,
				metricslegacy.Logger(logger),
				metricslegacy.Registry(reg),
				metricslegacy.HandlerInstrumenter(ins),
			))

		r.Mount("/api/metrics/v1",
			http.StripPrefix("/api/metrics/v1",
				metricsv1.NewHandler(
					cfg.metrics.readEndpoint,
					cfg.metrics.writeEndpoint,
					metricsv1.Logger(logger),
					metricsv1.Registry(reg),
					metricsv1.HandlerInstrumenter(ins),
				),
			),
		)

		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = "/api/metrics/v1/graph"
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
		})

		s := http.Server{
			Addr:         cfg.server.listen,
			Handler:      r,
			TLSConfig:    tlsConfig,
			ReadTimeout:  2 * time.Minute, // best set per handler
			WriteTimeout: 2 * time.Minute, // best set per handler
		}

		g.Add(func() error {
			level.Info(logger).Log("msg", "starting the HTTP server", "address", cfg.server.listen)

			if tlsConfig != nil {
				// certFile and keyFile passed in TLSConfig at initialization.
				return s.ListenAndServeTLS("", "")
			}

			return s.ListenAndServe()
		}, func(err error) {
			// gracePeriod is duration the server gracefully shuts down.
			const gracePeriod = 2 * time.Minute

			ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
			defer cancel()

			level.Info(logger).Log("msg", "shutting down the HTTP server")
			_ = s.Shutdown(ctx)
		})
	}
	{
		h := internalserver.NewHandler(
			internalserver.WithName("Internal - Observatorium API"),
			internalserver.WithHealthchecks(healthchecks),
			internalserver.WithPrometheusRegistry(reg),
			internalserver.WithPProf(),
		)

		s := http.Server{
			Addr:    cfg.server.listenInternal,
			Handler: h,
		}

		g.Add(func() error {
			level.Info(logger).Log("msg", "starting internal HTTP server", "address", s.Addr)
			return s.ListenAndServe()
		}, func(err error) {
			_ = s.Shutdown(context.Background())
		})
	}

	if err := g.Run(); err != nil {
		stdlog.Fatal(err)
	}
}

func parseFlags(logger log.Logger) (config, error) {
	var (
		rawTLSCipherSuites      string
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
		"The address on which public server runs.")
	flag.StringVar(&cfg.server.listenInternal, "web.internal.listen", ":8081",
		"The address on which internal server runs.")
	flag.StringVar(&cfg.server.healthcheckURL, "web.healthchecks.url", "http://localhost:8080",
		"The URL on which public server runs and to run healthchecks against.")
	flag.StringVar(&rawMetricsReadEndpoint, "metrics.read.endpoint", "",
		"The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.")
	flag.StringVar(&rawMetricsWriteEndpoint, "metrics.write.endpoint", "",
		"The endpoint against which to make write requests for metrics.")
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
