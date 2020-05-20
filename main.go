package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	rbacproxytls "github.com/brancz/kube-rbac-proxy/pkg/tls"
	"github.com/ghodss/yaml"
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
	"github.com/observatorium/observatorium/internal/authentication"
	"github.com/observatorium/observatorium/internal/authorization"
	"github.com/observatorium/observatorium/internal/server"
	"github.com/observatorium/observatorium/internal/tls"
	"github.com/observatorium/observatorium/rbac"
)

type config struct {
	logLevel  string
	logFormat string

	rbacConfigPath    string
	tenantsConfigPath string

	debug   debugConfig
	server  serverConfig
	tls     tlsConfig
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
}

type tlsConfig struct {
	certFile       string
	keyFile        string
	clientCAFile   string
	minVersion     string
	cipherSuites   []string
	reloadInterval time.Duration
}

type metricsConfig struct {
	readEndpoint  *url.URL
	writeEndpoint *url.URL
	tenantHeader  string
}

const (
	readTimeout = 2 * time.Minute
	writeTimeout
	gracePeriod
	middlewareTimeout
)

func main() {
	cfg, err := parseFlags()
	if err != nil {
		stdlog.Fatalf("parse flag: %v", err)
	}

	type tenant struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		OIDC struct {
			ClientID      string `json:"clientID"`
			ClientSecret  string `json:"clientSecret"`
			IssuerURL     string `json:"issuerURL"`
			RedirectURL   string `json:"redirectURL"`
			UsernameClaim string `json:"usernameClaim"`
		} `json:"oidc"`
	}

	type tenantsConfig struct {
		Tenants []tenant `json:"tenants"`
	}

	var tenantsCfg tenantsConfig
	{
		f, err := ioutil.ReadFile(cfg.tenantsConfigPath)
		if err != nil {
			stdlog.Fatalf("cannot read tenant configuration file from path %s: %v", cfg.tenantsConfigPath, err)
		}

		if err := yaml.Unmarshal(f, &tenantsCfg); err != nil {
			stdlog.Fatalf("unable to read tenant YAML: %v", err)
		}
	}

	var authorizer rbac.Authorizer
	{
		f, err := os.Open(cfg.rbacConfigPath)
		if err != nil {
			stdlog.Fatalf("cannot read RBAC configuration file from path %s: %v", cfg.rbacConfigPath, err)
		}
		defer f.Close()
		if authorizer, err = rbac.Parse(f); err != nil {
			stdlog.Fatalf("unable to read RBAC YAML: %v", err)
		}
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
					http.StatusNotFound,
					time.Second,
				),
			)
		}

		r := chi.NewRouter()
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Recoverer)
		r.Use(middleware.StripSlashes)
		r.Use(middleware.Timeout(middlewareTimeout)) // best set per handler
		r.Use(server.Logger(logger))

		ins := server.NewInstrumentationMiddleware(reg)

		r.Group(func(r chi.Router) {
			r.Use(authentication.WithTenant)

			tenantIDs := make(map[string]string)
			var oidcs []authentication.OIDCConfig
			for _, t := range tenantsCfg.Tenants {
				level.Info(logger).Log("msg", "adding a tenant", "tenant", t.Name)
				tenantIDs[t.Name] = t.ID
				oidcs = append(oidcs, authentication.OIDCConfig{
					Tenant:        t.Name,
					ClientID:      t.OIDC.ClientID,
					ClientSecret:  t.OIDC.ClientSecret,
					IssuerURL:     t.OIDC.IssuerURL,
					RedirectURL:   t.OIDC.RedirectURL,
					UsernameClaim: t.OIDC.UsernameClaim,
				})
			}

			oidcHandler, oidcMiddleware, err := authentication.NewOIDCHandler(oidcs...)
			if err != nil {
				stdlog.Fatalf("failed to create OIDC handler: %v", err)
			}
			r.Mount("/oidc/{tenant}", oidcHandler)

			r.Group(func(r chi.Router) {
				r.Use(oidcMiddleware)
				r.Use(authentication.WithTenantHeader(cfg.metrics.tenantHeader, tenantIDs))

				r.HandleFunc("/{tenant}", func(w http.ResponseWriter, r *http.Request) {
					tenant, ok := authentication.GetTenant(r.Context())
					if !ok {
						w.WriteHeader(http.StatusNotFound)
						return
					}

					http.Redirect(w, r, path.Join("/api/metrics/v1/", tenant, "graph"), http.StatusMovedPermanently)
				})

				r.Mount("/api/v1/{tenant}",
					metricslegacy.NewHandler(
						cfg.metrics.readEndpoint,
						metricslegacy.Logger(logger),
						metricslegacy.Registry(reg),
						metricslegacy.HandlerInstrumenter(ins),
						metricslegacy.ReadMiddleware(authorization.WithAuthorizer(authorizer, rbac.Read, "metrics")),
					),
				)

				r.Mount("/api/metrics/v1/{tenant}",
					StripTenantPrefix("/api/metrics/v1",
						metricsv1.NewHandler(
							cfg.metrics.readEndpoint,
							cfg.metrics.writeEndpoint,
							metricsv1.Logger(logger),
							metricsv1.Registry(reg),
							metricsv1.HandlerInstrumenter(ins),
							metricsv1.ReadMiddleware(authorization.WithAuthorizer(authorizer, rbac.Read, "metrics")),
							metricsv1.WriteMiddleware(authorization.WithAuthorizer(authorizer, rbac.Write, "metrics")),
						),
					),
				)
			})
		})

		s := http.Server{
			Addr:         cfg.server.listen,
			Handler:      r,
			TLSConfig:    tlsConfig,
			ReadTimeout:  readTimeout,  // best set per handler
			WriteTimeout: writeTimeout, // best set per handler
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
			const gracePeriod = gracePeriod

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

func parseFlags() (config, error) {
	var (
		rawTLSCipherSuites      string
		rawMetricsReadEndpoint  string
		rawMetricsWriteEndpoint string
	)

	cfg := config{}

	flag.StringVar(&cfg.rbacConfigPath, "rbac.config", "rbac.yaml",
		"Path to the RBAC configuration file.")
	flag.StringVar(&cfg.tenantsConfigPath, "tenants.config", "tenants.yaml",
		"Path to the tenants file.")
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
	flag.StringVar(&cfg.metrics.tenantHeader, "metrics.tenant-header", "THANOS-TENANT",
		"The name of the HTTP header containing the tenant ID to forward to the metrics upstreams.")
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

func StripTenantPrefix(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := authentication.GetTenant(r.Context())
		if !ok {
			http.Error(w, "tenant not found", http.StatusInternalServerError)
			return
		}
		http.StripPrefix(path.Join("/", prefix, tenant), next).ServeHTTP(w, r)
	})
}
