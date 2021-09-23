package main

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
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
	"github.com/metalmatze/signal/server/signalhttp"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/version"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.uber.org/automaxprocs/maxprocs"

	logsv1 "github.com/observatorium/api/api/logs/v1"
	metricslegacy "github.com/observatorium/api/api/metrics/legacy"
	metricsv1 "github.com/observatorium/api/api/metrics/v1"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/logger"
	"github.com/observatorium/api/opa"
	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/ratelimit"
	"github.com/observatorium/api/rbac"
	"github.com/observatorium/api/server"
	"github.com/observatorium/api/tls"
	"github.com/observatorium/api/tracing"
)

const (
	readTimeout  = 15 * time.Minute
	writeTimeout = 2 * time.Minute
	gracePeriod
	middlewareTimeout
	grpcDialTimeout = 1 * time.Second
)

type config struct {
	logLevel  string
	logFormat string

	rbacConfigPath    string
	tenantsConfigPath string

	debug           debugConfig
	server          serverConfig
	tls             tlsConfig
	metrics         metricsConfig
	logs            logsConfig
	middleware      middlewareConfig
	internalTracing internalTracingConfig
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
	minVersion     string
	cipherSuites   []string
	reloadInterval time.Duration

	serverCertFile string
	serverKeyFile  string

	internalServerCertFile string
	internalServerKeyFile  string

	healthchecksServerCAFile string
	healthchecksServerName   string
}

type metricsConfig struct {
	readEndpoint  *url.URL
	writeEndpoint *url.URL
	tenantHeader  string
	tenantLabel   string
	// enable metrics if at least one {read|write}Endpoint} is provided.
	enabled bool
}

type logsConfig struct {
	readEndpoint  *url.URL
	writeEndpoint *url.URL
	tailEndpoint  *url.URL
	tenantHeader  string
	// enable logs at least one {read,write,tail}Endpoint} is provided.
	enabled bool
}

type middlewareConfig struct {
	rateLimiterAddress                string
	concurrentRequestLimit            int
	backLogLimitConcurrentRequests    int
	backLogDurationConcurrentRequests time.Duration
}

type internalTracingConfig struct {
	serviceName      string
	endpoint         string
	endpointType     tracing.EndpointType
	samplingFraction float64
}

//nolint:funlen,gocyclo,gocognit
func main() {
	cfg, err := parseFlags()
	if err != nil {
		stdlog.Fatalf("parse flag: %v", err)
	}

	if !cfg.metrics.enabled && !cfg.logs.enabled {
		stdlog.Fatal("Neither logging nor metrics endpoints are enabled. " +
			"Specifying at least a logging or a metrics endpoint is mandatory")
	}

	logger := logger.NewLogger(cfg.logLevel, cfg.logFormat, cfg.debug.name)
	defer level.Info(logger).Log("msg", "exiting")

	tp, closer, err := tracing.InitTracer(
		cfg.internalTracing.serviceName,
		cfg.internalTracing.endpoint,
		cfg.internalTracing.endpointType,
		cfg.internalTracing.samplingFraction,
	)
	if err != nil {
		stdlog.Fatalf("initialize tracer: %v", err)
	}

	defer closer()

	otel.SetErrorHandler(otelErrorHandler{logger: logger})

	type tenant struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		OIDC *struct {
			ClientID      string `json:"clientID"`
			ClientSecret  string `json:"clientSecret"`
			GroupClaim    string `json:"groupClaim"`
			IssuerRawCA   []byte `json:"issuerCA"`
			IssuerCAPath  string `json:"issuerCAPath"`
			issuerCA      *x509.Certificate
			IssuerURL     string `json:"issuerURL"`
			RedirectURL   string `json:"redirectURL"`
			UsernameClaim string `json:"usernameClaim"`
		} `json:"oidc"`
		MTLS *struct {
			RawCA  []byte `json:"ca"`
			CAPath string `json:"caPath"`
			cas    []*x509.Certificate
		} `json:"mTLS"`
		OPA *struct {
			Query           string   `json:"query"`
			Paths           []string `json:"paths"`
			URL             string   `json:"url"`
			WithAccessToken bool     `json:"withAccessToken"`
			authorizer      rbac.Authorizer
		} `json:"opa"`
		RateLimits []*struct {
			Endpoint string   `json:"endpoint"`
			Limit    int      `json:"limit"`
			Window   duration `json:"window"`
		} `json:"rateLimits"`
	}

	type tenantsConfig struct {
		Tenants []*tenant `json:"tenants"`
	}

	var tenantsCfg tenantsConfig
	{
		f, err := ioutil.ReadFile(cfg.tenantsConfigPath)
		if err != nil {
			stdlog.Fatalf("cannot read tenant configuration file from path %q: %v", cfg.tenantsConfigPath, err)
		}

		if err := yaml.Unmarshal(f, &tenantsCfg); err != nil {
			stdlog.Fatalf("unable to read tenant YAML: %v", err)
		}

		skip := level.Warn(log.With(logger, "msg", "skipping invalid tenant"))
		for i, t := range tenantsCfg.Tenants {
			if t.OIDC != nil {
				if t.OIDC.IssuerCAPath != "" {
					t.OIDC.IssuerRawCA, err = ioutil.ReadFile(t.OIDC.IssuerCAPath)
					if err != nil {
						skip.Log("tenant", t.Name, "err", fmt.Sprintf("cannot read issuer CA certificate file from path %q: %v", t.OIDC.IssuerCAPath, err))
						tenantsCfg.Tenants[i] = nil
						continue
					}
				}
				if len(t.OIDC.IssuerRawCA) != 0 {
					block, _ := pem.Decode(t.OIDC.IssuerRawCA)
					if block == nil {
						skip.Log("tenant", t.Name, "err", "failed to parse issuer CA certificate PEM")
						tenantsCfg.Tenants[i] = nil
						continue
					}
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse issuer certificate: %v", err))
						tenantsCfg.Tenants[i] = nil
						continue
					}
					t.OIDC.issuerCA = cert
				}
			}
			if t.MTLS != nil {
				if t.MTLS.CAPath != "" {
					t.MTLS.RawCA, err = ioutil.ReadFile(t.MTLS.CAPath)
					if err != nil {
						skip.Log("tenant", t.Name, "err", fmt.Sprintf("cannot read CA certificate file from path %q: %v", t.OIDC.IssuerCAPath, err))
						tenantsCfg.Tenants[i] = nil
						continue
					}
				}
				var (
					block *pem.Block
					rest  []byte = t.MTLS.RawCA
					cert  *x509.Certificate
				)
				for {
					block, rest = pem.Decode(rest)
					if block == nil {
						skip.Log("tenant", t.Name, "err", "failed to parse CA certificate PEM")
						tenantsCfg.Tenants[i] = nil
						break
					}
					cert, err = x509.ParseCertificate(block.Bytes)
					if err != nil {
						skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse CA certificate: %v", err))
						tenantsCfg.Tenants[i] = nil
						break
					}
					t.MTLS.cas = append(t.MTLS.cas, cert)
					if len(rest) == 0 {
						break
					}
				}
			}
			if t.OPA != nil {
				if t.OPA.URL != "" {
					u, err := url.Parse(t.OPA.URL)
					if err != nil {
						skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse OPA URL: %v", err))
						tenantsCfg.Tenants[i] = nil
						continue
					}
					t.OPA.authorizer = opa.NewRESTAuthorizer(u,
						opa.LoggerOption(log.With(logger, "tenant", t.Name)),
						opa.AccessTokenOption(t.OPA.WithAccessToken),
					)
				} else {
					a, err := opa.NewInProcessAuthorizer(t.OPA.Query, t.OPA.Paths,
						opa.LoggerOption(log.With(logger, "tenant", t.Name)),
						opa.AccessTokenOption(t.OPA.WithAccessToken),
					)
					if err != nil {
						skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to create in-process OPA authorizer: %v", err))
						tenantsCfg.Tenants[i] = nil
						continue
					}
					t.OPA.authorizer = a
				}
			}
		}
	}

	var authorizer rbac.Authorizer
	{
		f, err := os.Open(cfg.rbacConfigPath)
		if err != nil {
			stdlog.Fatalf("cannot read RBAC configuration file from path %q: %v", cfg.rbacConfigPath, err)
		}
		defer f.Close()
		if authorizer, err = rbac.Parse(f); err != nil {
			stdlog.Fatalf("unable to read RBAC YAML: %v", err)
		}
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		version.NewCollector("observatorium"),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
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

	var rateLimitClient *ratelimit.Client

	if cfg.middleware.rateLimiterAddress != "" {
		ctx, cancel := context.WithTimeout(context.Background(), grpcDialTimeout)
		defer cancel()

		rateLimitClient = ratelimit.NewClient(reg)
		if err := rateLimitClient.Dial(ctx, cfg.middleware.rateLimiterAddress); err != nil {
			stdlog.Fatal(err)
		}
	}

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
	{
		if cfg.server.healthcheckURL != "" {
			t := (http.DefaultTransport).(*http.Transport).Clone()
			t.TLSClientConfig = &stdtls.Config{
				ServerName: cfg.tls.healthchecksServerName,
			}

			if cfg.tls.healthchecksServerCAFile != "" {
				caCert, err := ioutil.ReadFile(cfg.tls.healthchecksServerCAFile)
				if err != nil {
					stdlog.Fatalf("failed to initialize healthcheck server TLS CA: %v", err)
				}
				t.TLSClientConfig.RootCAs = x509.NewCertPool()
				t.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCert)
			}

			// checks if server is up
			healthchecks.AddLivenessCheck("http",
				healthcheck.HTTPCheckClient(
					&http.Client{Transport: t},
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
		r.Use(middleware.Timeout(middlewareTimeout)) // best set per handler.
		// With default value of zero backlog concurrent requests crossing a rate-limit result in non-200 HTTP response.
		r.Use(middleware.ThrottleBacklog(cfg.middleware.concurrentRequestLimit,
			cfg.middleware.backLogLimitConcurrentRequests, cfg.middleware.backLogDurationConcurrentRequests))
		r.Use(server.Logger(logger))

		ins := signalhttp.NewHandlerInstrumenter(reg, []string{"group", "handler"})

		r.Group(func(r chi.Router) {
			tenantIDs := map[string]string{}
			var oidcs []authentication.TenantOIDCConfig
			var mTLSs []authentication.MTLSConfig
			authorizers := map[string]rbac.Authorizer{}
			var rateLimits []ratelimit.Config
			for _, t := range tenantsCfg.Tenants {
				if t == nil {
					continue
				}
				level.Info(logger).Log("msg", "adding a tenant", "tenant", t.Name)
				tenantIDs[t.Name] = t.ID
				if t.RateLimits != nil {
					for _, rl := range t.RateLimits {
						matcher, err := regexp.Compile(rl.Endpoint)
						if err != nil {
							level.Warn(logger).Log("msg", "failed to compile matcher for rate limiter", "err", err)
						}
						rateLimits = append(rateLimits, ratelimit.Config{
							Tenant:  t.Name,
							Matcher: matcher,
							Limit:   rl.Limit,
							Window:  time.Duration(rl.Window),
						})
					}
				}
				switch {
				case t.OIDC != nil:
					oidcs = append(oidcs, authentication.TenantOIDCConfig{
						Tenant: t.Name,
						OIDCConfig: authentication.OIDCConfig{
							ClientID:      t.OIDC.ClientID,
							ClientSecret:  t.OIDC.ClientSecret,
							GroupClaim:    t.OIDC.GroupClaim,
							IssuerCA:      t.OIDC.issuerCA,
							IssuerURL:     t.OIDC.IssuerURL,
							RedirectURL:   t.OIDC.RedirectURL,
							UsernameClaim: t.OIDC.UsernameClaim,
						},
					})
				case t.MTLS != nil:
					mTLSs = append(mTLSs, authentication.MTLSConfig{
						Tenant: t.Name,
						CAs:    t.MTLS.cas,
					})
				default:
					stdlog.Fatalf("tenant %q must specify either an OIDC or an mTLS configuration", t.Name)
				}
				if t.OPA != nil {
					authorizers[t.Name] = t.OPA.authorizer
				} else {
					authorizers[t.Name] = authorizer
				}
			}

			r.Use(authentication.WithTenant)
			r.Use(authentication.WithTenantID(tenantIDs))
			r.Use(authentication.WithAccessToken())

			mTLSMiddlewareFunc := authentication.NewMTLS(mTLSs)
			oh := authentication.NewOIDCHandlers(logger, reg)
			for _, oidc := range oidcs {
				oh.AddOIDCForTenant("/oidc/{tenant}", oidc)
			}
			r.Mount("/oidc/{tenant}", oh.Router())

			// Metrics.
			if cfg.metrics.enabled {
				r.Group(func(r chi.Router) {
					r.Use(authentication.WithTenantMiddlewares(oh.GetTenantMiddleware, mTLSMiddlewareFunc))
					r.Use(authentication.WithTenantHeader(cfg.metrics.tenantHeader, tenantIDs))
					if rateLimitClient != nil {
						r.Use(ratelimit.WithSharedRateLimiter(logger, rateLimitClient, rateLimits...))
					} else {
						r.Use(ratelimit.WithLocalRateLimiter(rateLimits...))
					}

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
							metricslegacy.WithLogger(logger),
							metricslegacy.WithRegistry(reg),
							metricslegacy.WithHandlerInstrumenter(ins),
							metricslegacy.WithSpanRoutePrefix("/api/v1/{tenant}"),
							metricslegacy.WithQueryMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
							metricslegacy.WithQueryMiddleware(metricsv1.WithEnforceTenancyOnQuery(cfg.metrics.tenantLabel)),
							metricslegacy.WithUIMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
						),
					)

					r.Mount("/api/metrics/v1/{tenant}",
						stripTenantPrefix("/api/metrics/v1",
							metricsv1.NewHandler(
								cfg.metrics.readEndpoint,
								cfg.metrics.writeEndpoint,
								metricsv1.WithLogger(logger),
								metricsv1.WithRegistry(reg),
								metricsv1.WithHandlerInstrumenter(ins),
								metricsv1.WithSpanRoutePrefix("/api/metrics/v1/{tenant}"),
								metricsv1.WithQueryMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
								metricsv1.WithQueryMiddleware(metricsv1.WithEnforceTenancyOnQuery(cfg.metrics.tenantLabel)),
								metricsv1.WithReadMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
								metricsv1.WithReadMiddleware(metricsv1.WithEnforceTenancyOnMatchers(cfg.metrics.tenantLabel)),
								metricsv1.WithUIMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
								metricsv1.WithWriteMiddleware(authorization.WithAuthorizers(authorizers, rbac.Write, "metrics")),
							),
						),
					)
				})
			}

			// Logs.
			if cfg.logs.enabled {
				r.Group(func(r chi.Router) {
					r.Use(authentication.WithTenantMiddlewares(oh.GetTenantMiddleware, mTLSMiddlewareFunc))
					r.Use(authentication.WithTenantHeader(cfg.logs.tenantHeader, tenantIDs))

					r.Mount("/api/logs/v1/{tenant}",
						stripTenantPrefix("/api/logs/v1",
							logsv1.NewHandler(
								cfg.logs.readEndpoint,
								cfg.logs.tailEndpoint,
								cfg.logs.writeEndpoint,
								logsv1.Logger(logger),
								logsv1.WithRegistry(reg),
								logsv1.WithHandlerInstrumenter(ins),
								logsv1.WithSpanRoutePrefix("/api/logs/v1/{tenant}"),
								logsv1.WithReadMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "logs")),
								logsv1.WithWriteMiddleware(authorization.WithAuthorizers(authorizers, rbac.Write, "logs")),
							),
						),
					)
				})
			}
		})

		tlsConfig, err := tls.NewServerConfig(
			log.With(logger, "protocol", "HTTP"),
			cfg.tls.serverCertFile,
			cfg.tls.serverKeyFile,
			cfg.tls.minVersion,
			cfg.tls.cipherSuites,
		)
		if err != nil {
			stdlog.Fatalf("failed to initialize tls config: %v", err)
		}

		if tlsConfig != nil {
			r, err := rbacproxytls.NewCertReloader(
				cfg.tls.serverCertFile,
				cfg.tls.serverKeyFile,
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

		s := http.Server{
			Addr:         cfg.server.listen,
			Handler:      otelhttp.NewHandler(r, "api", otelhttp.WithTracerProvider(tp)),
			TLSConfig:    tlsConfig,
			ReadTimeout:  readTimeout,  // best set per handler.
			WriteTimeout: writeTimeout, // best set per handler.
		}

		g.Add(func() error {
			level.Info(logger).Log("msg", "starting the HTTP server", "address", cfg.server.listen)

			if tlsConfig != nil {
				// serverCertFile and serverKeyFile passed in TLSConfig at initialization.
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

		internalTLSConfig, err := tls.NewServerConfig(
			log.With(logger, "protocol", "HTTP"),
			cfg.tls.internalServerCertFile,
			cfg.tls.internalServerKeyFile,
			cfg.tls.minVersion,
			cfg.tls.cipherSuites,
		)
		if err != nil {
			stdlog.Fatalf("failed to initialize tls config: %v", err)
		}

		if internalTLSConfig != nil {
			r, err := rbacproxytls.NewCertReloader(
				cfg.tls.internalServerCertFile,
				cfg.tls.internalServerKeyFile,
				cfg.tls.reloadInterval,
			)
			if err != nil {
				stdlog.Fatalf("failed to initialize certificate reloader: %v", err)
			}

			internalTLSConfig.GetCertificate = r.GetCertificate

			ctx, cancel := context.WithCancel(context.Background())
			g.Add(func() error {
				return r.Watch(ctx)
			}, func(error) {
				cancel()
			})
		}

		s := http.Server{
			Addr:         cfg.server.listenInternal,
			Handler:      h,
			TLSConfig:    internalTLSConfig,
			ReadTimeout:  readTimeout,  // best set per handler.
			WriteTimeout: writeTimeout, // best set per handler.
		}

		g.Add(func() error {
			level.Info(logger).Log("msg", "starting internal HTTP server", "address", s.Addr)

			if internalTLSConfig != nil {
				// internalServerCertFile and internalServerKeyFile passed in TLSConfig at initialization.
				return s.ListenAndServeTLS("", "")
			}

			return s.ListenAndServe()
		}, func(err error) {
			_ = s.Shutdown(context.Background())
		})
	}

	if err := g.Run(); err != nil {
		stdlog.Fatal(err)
	}
}

// Configuration helpers.

type duration time.Duration

func (d duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch value := v.(type) {
	case float64:
		*d = duration(time.Duration(value))

		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}

		*d = duration(tmp)

		return nil
	default:
		return errors.New("invalid duration")
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
	flag.StringVar(&cfg.debug.name, "debug.name", "observatorium",
		"A name to add as a prefix to log lines.")
	flag.IntVar(&cfg.debug.mutexProfileFraction, "debug.mutex-profile-fraction", 10,
		"The percentage of mutex contention events that are reported in the mutex profile.")
	flag.IntVar(&cfg.debug.blockProfileRate, "debug.block-profile-rate", 10,
		"The percentage of goroutine blocking events that are reported in the blocking profile.")
	flag.StringVar(&cfg.logLevel, "log.level", "info",
		"The log filtering level. Options: 'error', 'warn', 'info', 'debug'.")
	flag.StringVar(&cfg.logFormat, "log.format", logger.LogFormatLogfmt,
		"The log format to use. Options: 'logfmt', 'json'.")
	flag.StringVar(&cfg.internalTracing.serviceName, "internal.tracing.service-name", "observatorium_api",
		"The service name to report to the tracing backend.")
	flag.StringVar(&cfg.internalTracing.endpoint, "internal.tracing.endpoint", "",
		"The full URL of the trace agent or collector. If it's not set, tracing will be disabled.")
	flag.StringVar(&rawTracingEndpointType, "internal.tracing.endpoint-type", string(tracing.EndpointTypeAgent),
		fmt.Sprintf("The tracing endpoint type. Options: '%s', '%s'.", tracing.EndpointTypeAgent, tracing.EndpointTypeCollector))
	flag.Float64Var(&cfg.internalTracing.samplingFraction, "internal.tracing.sampling-fraction", 0.1,
		"The fraction of traces to sample. Thus, if you set this to .5, half of traces will be sampled.")
	flag.StringVar(&cfg.server.listen, "web.listen", ":8080",
		"The address on which the public server listens.")
	flag.StringVar(&cfg.server.listenInternal, "web.internal.listen", ":8081",
		"The address on which the internal server listens.")
	flag.StringVar(&cfg.server.healthcheckURL, "web.healthchecks.url", "http://localhost:8080",
		"The URL against which to run healthchecks.")
	flag.StringVar(&rawLogsTailEndpoint, "logs.tail.endpoint", "",
		"The endpoint against which to make tail read requests for logs.")
	flag.StringVar(&rawLogsReadEndpoint, "logs.read.endpoint", "",
		"The endpoint against which to make read requests for logs.")
	flag.StringVar(&cfg.logs.tenantHeader, "logs.tenant-header", "X-Scope-OrgID",
		"The name of the HTTP header containing the tenant ID to forward to the logs upstream.")
	flag.StringVar(&rawLogsWriteEndpoint, "logs.write.endpoint", "",
		"The endpoint against which to make write requests for logs.")
	flag.StringVar(&rawMetricsReadEndpoint, "metrics.read.endpoint", "",
		"The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.")
	flag.StringVar(&rawMetricsWriteEndpoint, "metrics.write.endpoint", "",
		"The endpoint against which to make write requests for metrics.")
	flag.StringVar(&cfg.metrics.tenantHeader, "metrics.tenant-header", "THANOS-TENANT",
		"The name of the HTTP header containing the tenant ID to forward to the metrics upstreams.")
	flag.StringVar(&cfg.metrics.tenantLabel, "metrics.tenant-label", "tenant_id",
		"The name of the PromQL label that should hold the tenant ID in metrics upstreams.")
	flag.StringVar(&cfg.tls.serverCertFile, "tls.server.cert-file", "",
		"File containing the default x509 Certificate for HTTPS. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.serverKeyFile, "tls.server.key-file", "",
		"File containing the default x509 private key matching --tls.server.cert-file. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.internalServerCertFile, "tls.internal.server.cert-file", "",
		"File containing the default x509 Certificate for internal HTTPS. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.internalServerKeyFile, "tls.internal.server.key-file", "",
		"File containing the default x509 private key matching --tls.internal.server.cert-file. Leave blank to disable TLS.")
	flag.StringVar(&cfg.tls.healthchecksServerCAFile, "tls.healthchecks.server-ca-file", "",
		"File containing the TLS CA against which to verify servers."+
			" If no server CA is specified, the client will use the system certificates.")
	flag.StringVar(&cfg.tls.healthchecksServerName, "tls.healthchecks.server-name", "",
		"Server name is used to verify the hostname of the certificates returned by the server."+
			" If no server name is specified, the server name will be inferred from the healthcheck URL.")
	flag.StringVar(&cfg.tls.minVersion, "tls.min-version", "VersionTLS13",
		"Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flag.StringVar(&rawTLSCipherSuites, "tls.cipher-suites", "",
		"Comma-separated list of cipher suites for the server."+
			" Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants)."+
			" If omitted, the default Go cipher suites will be used."+
			" Note that TLS 1.3 ciphersuites are not configurable.")
	flag.DurationVar(&cfg.tls.reloadInterval, "tls.reload-interval", time.Minute,
		"The interval at which to watch for TLS certificate changes.")
	flag.StringVar(&cfg.middleware.rateLimiterAddress, "middleware.rate-limiter.grpc-address", "",
		"The gRPC Server Address against which to run rate limit checks when the rate limits are specified for a given tenant."+
			" If not specified, local, non-shared rate limiting will be used.")
	flag.IntVar(&cfg.middleware.concurrentRequestLimit, "middleware.concurrent-request-limit", 10_000,
		"The limit that controls the number of concurrently processed requests across all tenants.")
	flag.IntVar(&cfg.middleware.backLogLimitConcurrentRequests, "middleware.backlog-limit-concurrent-requests", 0,
		"The number of concurrent requests that can buffered.")
	flag.DurationVar(&cfg.middleware.backLogDurationConcurrentRequests, "middleware.backlog-duration-concurrent-requests", 1*time.Millisecond,
		"The time duration to buffer up concurrent requests.")

	flag.Parse()

	if rawMetricsReadEndpoint != "" {
		cfg.metrics.enabled = true

		metricsReadEndpoint, err := url.ParseRequestURI(rawMetricsReadEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--metrics.read.endpoint %q is invalid: %w", rawMetricsReadEndpoint, err)
		}

		cfg.metrics.readEndpoint = metricsReadEndpoint
	}

	if rawMetricsWriteEndpoint != "" {
		cfg.metrics.enabled = true

		metricsWriteEndpoint, err := url.ParseRequestURI(rawMetricsWriteEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--metrics.write.endpoint %q is invalid: %w", rawMetricsWriteEndpoint, err)
		}

		cfg.metrics.writeEndpoint = metricsWriteEndpoint
	}

	if rawLogsReadEndpoint != "" {
		cfg.logs.enabled = true

		logsReadEndpoint, err := url.ParseRequestURI(rawLogsReadEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.read.endpoint is invalid, raw %s: %w", rawLogsReadEndpoint, err)
		}

		cfg.logs.readEndpoint = logsReadEndpoint
	}

	if rawLogsTailEndpoint != "" {
		cfg.logs.enabled = true

		logsTailEndpoint, err := url.ParseRequestURI(rawLogsTailEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.tail.endpoint is invalid, raw %s: %w", rawLogsTailEndpoint, err)
		}

		cfg.logs.tailEndpoint = logsTailEndpoint
	}

	if rawLogsWriteEndpoint != "" {
		cfg.logs.enabled = true

		logsWriteEndpoint, err := url.ParseRequestURI(rawLogsWriteEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.write.endpoint is invalid, raw %s: %w", rawLogsWriteEndpoint, err)
		}

		cfg.logs.writeEndpoint = logsWriteEndpoint
	}

	if rawTLSCipherSuites != "" {
		cfg.tls.cipherSuites = strings.Split(rawTLSCipherSuites, ",")
	}

	cfg.internalTracing.endpointType = tracing.EndpointType(rawTracingEndpointType)

	return cfg, nil
}

func stripTenantPrefix(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := authentication.GetTenant(r.Context())
		if !ok {
			http.Error(w, "tenant not found", http.StatusInternalServerError)
			return
		}

		tenantPrefix := path.Join("/", prefix, tenant)
		http.StripPrefix(tenantPrefix, proxy.WithPrefix(tenantPrefix, next)).ServeHTTP(w, r)
	})
}

type otelErrorHandler struct {
	logger log.Logger
}

func (oh otelErrorHandler) Handle(err error) {
	level.Error(oh.logger).Log("msg", "opentelemetry", "err", err.Error())
}
