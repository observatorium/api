package main

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	rbacproxytls "github.com/brancz/kube-rbac-proxy/pkg/tls"
	"github.com/ghodss/yaml"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/metalmatze/signal/healthcheck"
	"github.com/metalmatze/signal/internalserver"
	grpcproxy "github.com/mwitkow/grpc-proxy/proxy"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/version"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.uber.org/automaxprocs/maxprocs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	logsv1 "github.com/observatorium/api/api/logs/v1"
	metricslegacy "github.com/observatorium/api/api/metrics/legacy"
	metricsv1 "github.com/observatorium/api/api/metrics/v1"
	tracesv1 "github.com/observatorium/api/api/traces/v1"
	"github.com/observatorium/api/authentication"

	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"
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
	// Global HTTP server request/response timeouts.
	readHeaderTimeout = 1 * time.Second
	readTimeout       = 5 * time.Second
	writeTimeout      = 12 * time.Minute // Aligned with the slowest middleware handler.

	// Per Handler request context timeout.
	logsMiddlewareTimeout    = 10 * time.Minute
	metricsMiddlewareTimeout = 2 * time.Minute
	tracesMiddlewareTimeout  = 2 * time.Minute

	// GRPC dial timeout for traces handlers.
	grpcDialTimeout = 1 * time.Second

	// Server shutdown grace period.
	gracePeriod = 2 * time.Minute
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
	traces          tracesConfig
	middleware      middlewareConfig
	internalTracing internalTracingConfig
}

type debugConfig struct {
	mutexProfileFraction int
	blockProfileRate     int
	name                 string
}

type serverConfig struct {
	listen            string
	listenInternal    string
	healthcheckURL    string
	grpcListen        string
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
}

type tlsConfig struct {
	minVersion     string
	maxVersion     string
	cipherSuites   []string
	clientAuthType string
	reloadInterval time.Duration

	serverCertFile string
	serverKeyFile  string

	internalServerCertFile string
	internalServerKeyFile  string

	healthchecksServerCAFile string
	healthchecksServerName   string
}

type metricsConfig struct {
	readEndpoint         *url.URL
	writeEndpoint        *url.URL
	rulesEndpoint        *url.URL
	upstreamWriteTimeout time.Duration
	upstreamCAFile       string
	upstreamCertFile     string
	upstreamKeyFile      string
	tenantHeader         string
	tenantLabel          string
	// enable metrics if at least one {read|write}Endpoint} is provided.
	enabled bool
}

type logsConfig struct {
	readEndpoint         *url.URL
	writeEndpoint        *url.URL
	tailEndpoint         *url.URL
	rulesEndpoint        *url.URL
	upstreamWriteTimeout time.Duration
	upstreamCAFile       string
	upstreamCertFile     string
	upstreamKeyFile      string
	tenantHeader         string
	tenantLabel          string
	// Allow only read-only access on rules
	rulesReadOnly     bool
	rulesLabelFilters map[string][]string
	// enable logs at least one {read,write,tail}Endpoint} is provided.
	enabled bool
}

type tracesConfig struct {
	// readTemplateEndpoint is of the form "http://jaeger-{tenant}-query:16686".
	readTemplateEndpoint string

	readEndpoint         *url.URL
	writeEndpoint        string
	upstreamWriteTimeout time.Duration
	upstreamCAFile       string
	upstreamCertFile     string
	upstreamKeyFile      string
	tenantHeader         string
	// enable traces if readTemplateEndpoint, readEndpoint, or writeEndpoint is provided.
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
		config        map[string]interface{}
	} `json:"oidc"`
	OpenShift *struct {
		KubeConfigPath string `json:"kubeconfig"`
		ServiceAccount string `json:"serviceAccount"`
		RedirectURL    string `json:"redirectURL"`
		CookieSecret   string `json:"cookieSecret"`
		config         map[string]interface{}
	} `json:"openshift"`
	Authenticator *struct {
		Type   string                 `json:"type"`
		Config map[string]interface{} `json:"config"`
	} `json:"authenticator"`

	MTLS *struct {
		RawCA  []byte `json:"ca"`
		CAPath string `json:"caPath"`
		cas    []*x509.Certificate
		config map[string]interface{}
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

//nolint:funlen,gocyclo,gocognit
func main() {
	cfg, err := parseFlags()
	if err != nil {
		stdlog.Fatalf("parse flag: %v", err)
	}

	if !cfg.metrics.enabled && !cfg.logs.enabled && !cfg.traces.enabled {
		stdlog.Fatal("Neither logging, metrics not traces endpoints are enabled. " +
			"Specifying at least a logging or a metrics endpoint is mandatory")
	}

	logger := logger.NewLogger(cfg.logLevel, cfg.logFormat, cfg.debug.name)
	defer level.Info(logger).Log("msg", "exiting")

	if err := tracing.InitTracer(
		cfg.internalTracing.serviceName,
		cfg.internalTracing.endpoint,
		cfg.internalTracing.endpointType,
		cfg.internalTracing.samplingFraction,
	); err != nil {
		stdlog.Fatalf("initialize tracer: %v", err)
	}

	otel.SetErrorHandler(otelErrorHandler{logger: logger})

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		version.NewCollector("observatorium"),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	skippedTenants := promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
		Namespace: "observatorium",
		Subsystem: "api",
		Name:      "tenants_skipped_invalid_configuration_total",
		Help:      "The number of tenants which have not been configured due to an invalid configuration.",
	}, []string{"tenant"})

	type tenantsConfig struct {
		Tenants []*tenant `json:"tenants"`
	}

	var tenantsCfg tenantsConfig
	{
		f, err := os.ReadFile(cfg.tenantsConfigPath)
		if err != nil {
			stdlog.Fatalf("cannot read tenant configuration file from path %q: %v", cfg.tenantsConfigPath, err)
		}

		if err := yaml.Unmarshal(f, &tenantsCfg); err != nil {
			stdlog.Fatalf("unable to read tenant YAML: %v", err)
		}

		skip := level.Warn(log.With(logger, "msg", "skipping invalid tenant"))
		for i, t := range tenantsCfg.Tenants {
			if t.OIDC != nil {
				oidcConfig, err := unmarshalLegacyAuthenticatorConfig(t.OIDC)
				if err != nil {
					skip.Log("msg", "failed to unmarshal legacy OIDC config", "err", err, "tenant", t.Name)
					skippedTenants.WithLabelValues(t.Name).Inc()
					tenantsCfg.Tenants[i] = nil
					continue
				}

				t.OIDC.config = oidcConfig
			}

			if t.MTLS != nil {
				mTLSConfig, err := unmarshalLegacyAuthenticatorConfig(t.MTLS)
				if err != nil {
					skip.Log("msg", "failed to unmarshal legacy mTLS config", "err", err, "tenant", t.Name)
					skippedTenants.WithLabelValues(t.Name).Inc()
					tenantsCfg.Tenants[i] = nil
					continue
				}
				t.MTLS.config = mTLSConfig
			}

			if t.OpenShift != nil {
				openshiftConfig, err := unmarshalLegacyAuthenticatorConfig(t.OpenShift)
				if err != nil {
					skip.Log("msg", "failed to unmarshal legacy openshift config", "err", err, "tenant", t.Name)
					skippedTenants.WithLabelValues(t.Name).Inc()
					tenantsCfg.Tenants[i] = nil
					continue
				}
				t.OpenShift.config = openshiftConfig
			}

			if t.Authenticator != nil {
				if t.Authenticator.Config == nil {
					skip.Log("tenant", t.Name, "err", "failed to find authenticator config")
					skippedTenants.WithLabelValues(t.Name).Inc()
					tenantsCfg.Tenants[i] = nil
					continue
				}
			}

			if t.OPA != nil {
				if t.OPA.URL != "" {
					u, err := url.Parse(t.OPA.URL)
					if err != nil {
						skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse OPA URL: %v", err))
						skippedTenants.WithLabelValues(t.Name).Inc()
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
						skippedTenants.WithLabelValues(t.Name).Inc()
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
		if authorizer, err = rbac.Parse(f, logger); err != nil {
			stdlog.Fatalf("unable to read RBAC YAML: %v", err)
		}
	}

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
				caCert, err := os.ReadFile(cfg.tls.healthchecksServerCAFile)
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
					http.StatusOK,
					time.Second,
				),
			)
		}

		var (
			metricsUpstreamCACert     []byte
			metricsUpstreamClientCert *stdtls.Certificate
			logsUpstreamCACert        []byte
			logsUpstreamClientCert    *stdtls.Certificate
			tracesUpstreamCACert      []byte
			tracesUpstreamClientCert  *stdtls.Certificate
		)

		if cfg.metrics.upstreamCAFile != "" {
			metricsUpstreamCACert, err = os.ReadFile(cfg.metrics.upstreamCAFile)
			if err != nil {
				stdlog.Fatalf("failed to read upstream metrics TLS CA: %v", err)
			}
		}

		if cfg.metrics.upstreamCertFile != "" && cfg.metrics.upstreamKeyFile != "" {
			clientCert, err := stdtls.LoadX509KeyPair(cfg.metrics.upstreamCertFile, cfg.metrics.upstreamKeyFile)
			if err != nil {
				stdlog.Fatalf("failed to read upstream metrics client TLS cert/key pair: %v", err)
			}
			metricsUpstreamClientCert = &clientCert
		}

		if cfg.logs.upstreamCAFile != "" {
			logsUpstreamCACert, err = os.ReadFile(cfg.logs.upstreamCAFile)
			if err != nil {
				stdlog.Fatalf("failed to read upstream logs TLS CA: %v", err)
			}

		}

		if cfg.logs.upstreamCertFile != "" && cfg.logs.upstreamKeyFile != "" {
			clientCert, err := stdtls.LoadX509KeyPair(cfg.logs.upstreamCertFile, cfg.logs.upstreamKeyFile)
			if err != nil {
				stdlog.Fatalf("failed to read upstream logs client TLS cert/key pair: %v", err)
			}
			logsUpstreamClientCert = &clientCert
		}

		if cfg.traces.upstreamCAFile != "" {
			tracesUpstreamCACert, err = os.ReadFile(cfg.traces.upstreamCAFile)
			if err != nil {
				stdlog.Fatalf("failed to read upstream traces TLS CA: %v", err)
			}

		}

		if cfg.traces.upstreamCertFile != "" && cfg.traces.upstreamKeyFile != "" {
			clientCert, err := stdtls.LoadX509KeyPair(cfg.traces.upstreamCertFile, cfg.traces.upstreamKeyFile)
			if err != nil {
				stdlog.Fatalf("failed to read upstream traces client TLS cert/key pair: %v", err)
			}
			tracesUpstreamClientCert = &clientCert
		}

		r := chi.NewRouter()
		r.Use(middleware.RequestID)
		r.Use(middleware.RealIP)
		r.Use(middleware.Recoverer)
		r.Use(middleware.StripSlashes)

		// With default value of zero backlog concurrent requests crossing a rate-limit result in non-200 HTTP response.
		r.Use(middleware.ThrottleBacklog(cfg.middleware.concurrentRequestLimit,
			cfg.middleware.backLogLimitConcurrentRequests, cfg.middleware.backLogDurationConcurrentRequests))
		r.Use(server.Logger(logger))

		hardcodedLabels := []string{"group", "handler"}
		instrumenter := server.NewInstrumentedHandlerFactory(reg, hardcodedLabels)

		var (
			tenantIDs   = map[string]string{}
			authorizers = map[string]rbac.Authorizer{}
			oidcTenants = map[string]struct{}{}

			rateLimits []ratelimit.Config
			// registrationRetryCount used by authenticator providers to count
			// registration failures per tenant.
			registerTenantsFailingMetric = authentication.RegisterTenantsFailingMetric(reg)
			pm                           = authentication.NewProviderManager(logger, registerTenantsFailingMetric)
		)

		r.Group(func(r chi.Router) {
			// Set up common middleware before mounting authN routes.
			for _, t := range tenantsCfg.Tenants {
				tenantIDs[t.Name] = t.ID
			}

			r.Use(authentication.WithTenant)
			r.Use(authentication.WithTenantID(tenantIDs))
			r.Use(authentication.WithAccessToken())
			r.MethodNotAllowed(blockNonDefinedMethods())

			// registeredAuthNRoutes is used to avoid double registration of the same pattern.
			var regMtx sync.RWMutex
			registeredAuthNRoutes := make(map[string]struct{})
			for _, t := range tenantsCfg.Tenants {
				level.Info(logger).Log("msg", "adding a tenant", "tenant", t.Name)
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

				authenticatorConfig, authenticatorType, err := tenantAuthenticatorConfig(t)
				if err != nil {
					stdlog.Fatalf(err.Error())
				}
				if authenticatorType == authentication.OIDCAuthenticatorType {
					oidcTenants[t.Name] = struct{}{}
				}

				go func(config map[string]interface{}, authType, tenant string) {
					initializedAuthenticator := <-pm.InitializeProvider(config, tenant, authType, registerTenantsFailingMetric, logger)
					if initializedAuthenticator != nil {
						pattern, _ := initializedAuthenticator.Handler()
						regMtx.Lock()
						defer regMtx.Unlock()
						if _, ok := registeredAuthNRoutes[pattern]; !ok && pattern != "" {
							registeredAuthNRoutes[pattern] = struct{}{}
							r.Mount(pattern, pm.PatternHandler(pattern))
						}
					}
				}(authenticatorConfig, authenticatorType, t.Name)

				if t.OPA != nil {
					authorizers[t.Name] = t.OPA.authorizer
				} else {
					authorizers[t.Name] = authorizer
				}
			}

			writePathRedirectProtection := authentication.EnforceAccessTokenPresentOnSignalWrite(oidcTenants)

			// Metrics.
			if cfg.metrics.enabled {
				rateLimitMiddleware := ratelimit.WithLocalRateLimiter(rateLimits...)
				if rateLimitClient != nil {
					rateLimitMiddleware = ratelimit.WithSharedRateLimiter(logger, rateLimitClient, rateLimits...)
				}

				metricsMiddlewares := []func(http.Handler) http.Handler{
					authentication.WithTenantMiddlewares(pm.Middlewares),
					authentication.WithTenantHeader(cfg.metrics.tenantHeader, tenantIDs),
					rateLimitMiddleware,
				}

				r.Group(func(r chi.Router) {
					r.HandleFunc("/{tenant}", func(w http.ResponseWriter, r *http.Request) {
						tenant, ok := authentication.GetTenant(r.Context())
						if !ok {
							w.WriteHeader(http.StatusNotFound)
							return
						}

						http.Redirect(w, r, path.Join("/api/metrics/v1/", tenant, "graph"), http.StatusMovedPermanently)
					})
				})

				r.Group(func(r chi.Router) {
					r.Use(middleware.Timeout(cfg.metrics.upstreamWriteTimeout))
					r.Mount("/api/v1/{tenant}", metricslegacy.NewHandler(
						cfg.metrics.readEndpoint,
						metricsUpstreamCACert,
						metricsUpstreamClientCert,
						metricslegacy.WithLogger(logger),
						metricslegacy.WithRegistry(reg),
						metricslegacy.WithLabelParser(chiLabelParser),
						metricslegacy.WithHandlerInstrumenter(instrumenter),
						metricslegacy.WithGlobalMiddleware(metricsMiddlewares...),
						metricslegacy.WithSpanRoutePrefix("/api/v1/{tenant}"),
						metricslegacy.WithQueryMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
						metricslegacy.WithQueryMiddleware(metricsv1.WithEnforceTenancyOnQuery(cfg.metrics.tenantLabel)),
						metricslegacy.WithUIMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
					))

					r.Mount("/api/metrics/v1/{tenant}", metricsv1.NewHandler(
						cfg.metrics.readEndpoint,
						cfg.metrics.writeEndpoint,
						cfg.metrics.rulesEndpoint,
						metricsUpstreamCACert,
						metricsUpstreamClientCert,
						metricsv1.WithLogger(logger),
						metricsv1.WithRegistry(reg),
						metricsv1.WithLabelParser(chiLabelParser),
						metricsv1.WithHandlerInstrumenter(instrumenter),
						metricsv1.WithSpanRoutePrefix("/api/metrics/v1/{tenant}"),
						metricsv1.WithTenantLabel(cfg.metrics.tenantLabel),
						metricsv1.WithWriteMiddleware(writePathRedirectProtection),
						metricsv1.WithGlobalMiddleware(metricsMiddlewares...),
						metricsv1.WithWriteMiddleware(authorization.WithAuthorizers(authorizers, rbac.Write, "metrics")),
						metricsv1.WithQueryMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
						metricsv1.WithQueryMiddleware(metricsv1.WithEnforceTenancyOnQuery(cfg.metrics.tenantLabel)),
						metricsv1.WithReadMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
						metricsv1.WithReadMiddleware(metricsv1.WithEnforceTenancyOnMatchers(cfg.metrics.tenantLabel)),
						metricsv1.WithReadMiddleware(metricsv1.WithEnforceAuthorizationLabels()),
						metricsv1.WithUIMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "metrics")),
					))
				})
			}

			// Logs.
			if cfg.logs.enabled {
				r.Group(func(r chi.Router) {
					r.Use(middleware.Timeout(cfg.logs.upstreamWriteTimeout))
					r.Mount("/api/logs/v1/{tenant}",
						stripTenantPrefix("/api/logs/v1",
							logsv1.NewHandler(
								cfg.logs.readEndpoint,
								cfg.logs.tailEndpoint,
								cfg.logs.writeEndpoint,
								cfg.logs.rulesEndpoint,
								cfg.logs.rulesReadOnly,
								logsUpstreamCACert,
								logsUpstreamClientCert,
								logsv1.Logger(logger),
								logsv1.WithRegistry(reg),
								logsv1.WithHandlerInstrumenter(instrumenter),
								logsv1.WithSpanRoutePrefix("/api/logs/v1/{tenant}"),
								logsv1.WithWriteMiddleware(writePathRedirectProtection),
								logsv1.WithGlobalMiddleware(authentication.WithTenantMiddlewares(pm.Middlewares)),
								logsv1.WithGlobalMiddleware(authentication.WithTenantHeader(cfg.logs.tenantHeader, tenantIDs)),
								logsv1.WithReadMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "logs")),
								logsv1.WithReadMiddleware(logsv1.WithEnforceAuthorizationLabels()),
								logsv1.WithWriteMiddleware(authorization.WithAuthorizers(authorizers, rbac.Write, "logs")),
								logsv1.WithRulesLabelFilters(cfg.logs.rulesLabelFilters),
								logsv1.WithRulesReadMiddleware(logsv1.WithEnforceTenantAsRuleNamespace()),
								logsv1.WithRulesReadMiddleware(logsv1.WithEnforceRulesLabelFilters(cfg.logs.rulesLabelFilters)),
								logsv1.WithRulesWriteMiddleware(logsv1.WithEnforceTenantAsRuleNamespace()),
								logsv1.WithRulesWriteMiddleware(logsv1.WithEnforceRuleLabels(cfg.logs.tenantLabel)),
							),
						),
					)
				})
			}

			// Traces.
			if cfg.traces.enabled && (cfg.traces.readEndpoint != nil || cfg.traces.readTemplateEndpoint != "") {
				r.Group(func(r chi.Router) {
					r.Use(authentication.WithTenantMiddlewares(pm.Middlewares))
					r.Use(authentication.WithTenantHeader(cfg.traces.tenantHeader, tenantIDs))
					r.Use(middleware.Timeout(cfg.traces.upstreamWriteTimeout))

					// There can only be one login UI per tenant.  Let metrics be the default; fall back to search
					if !cfg.metrics.enabled {
						r.HandleFunc("/{tenant}", func(w http.ResponseWriter, r *http.Request) {
							tenant, ok := authentication.GetTenant(r.Context())
							if !ok {
								w.WriteHeader(http.StatusNotFound)
								return
							}

							http.Redirect(w, r, path.Join("/api/traces/v1/", tenant, "search"), http.StatusMovedPermanently)
						})
					}

					r.Mount("/api/traces/v1/{tenant}",
						stripTenantPrefix("/api/traces/v1",
							tracesv1.NewV2Handler(
								cfg.traces.readEndpoint,
								cfg.traces.readTemplateEndpoint,
								tracesUpstreamCACert,
								tracesUpstreamClientCert,
								tracesv1.Logger(logger),
								tracesv1.WithRegistry(reg),
								tracesv1.WithHandlerInstrumenter(instrumenter),
								tracesv1.WithSpanRoutePrefix("/api/traces/v1/{tenant}"),
								tracesv1.WithReadMiddleware(authorization.WithAuthorizers(authorizers, rbac.Read, "traces")),
								tracesv1.WithReadMiddleware(logsv1.WithEnforceAuthorizationLabels()),
								tracesv1.WithWriteMiddleware(authorization.WithAuthorizers(authorizers, rbac.Write, "traces")),
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
			cfg.tls.maxVersion,
			cfg.tls.clientAuthType,
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

		r.Get("/", server.PathsHandlerFunc(logger, r.Routes()))

		s := http.Server{
			Addr: cfg.server.listen,
			// otel HTTP handler with global trace provider
			Handler:           otelhttp.NewHandler(r, "api"),
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: cfg.server.readHeaderTimeout,
			ReadTimeout:       cfg.server.readTimeout,
			WriteTimeout:      cfg.server.writeTimeout,
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

		if cfg.server.grpcListen != "" {
			gs, err := newGRPCServer(
				&cfg,
				cfg.traces.tenantHeader,
				tenantIDs,
				pm.GRPCMiddlewares,
				authorizers,
				logger,
				tracesUpstreamCACert,
				tracesUpstreamClientCert,
			)
			if err != nil {
				stdlog.Fatalf("failed to initialize gRPC server: %v", err)
			}

			var lis net.Listener

			g.Add(func() error {
				level.Info(logger).Log("msg", "starting the gRPC server", "address", cfg.server.grpcListen)

				lis, err = net.Listen("tcp", cfg.server.grpcListen)
				if err != nil {
					return err
				}

				return gs.Serve(lis)
			}, func(err error) {
				level.Info(logger).Log("msg", "shutting down the gRPC server")
				gs.GracefulStop()
				if lis != nil {
					_ = lis.Close()
				}
			})
		}
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
			cfg.tls.maxVersion,
			cfg.tls.clientAuthType,
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
			Addr:              cfg.server.listenInternal,
			Handler:           h,
			TLSConfig:         internalTLSConfig,
			ReadHeaderTimeout: cfg.server.readHeaderTimeout,
			ReadTimeout:       cfg.server.readTimeout,
			WriteTimeout:      cfg.server.writeTimeout,
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

//nolint:funlen,gocognit
func parseFlags() (config, error) {
	var (
		rawTLSCipherSuites      string
		rawMetricsReadEndpoint  string
		rawMetricsWriteEndpoint string
		rawMetricsRulesEndpoint string
		rawLogsReadEndpoint     string
		rawLogsRulesEndpoint    string
		rawLogsTailEndpoint     string
		rawLogsWriteEndpoint    string
		rawLogsRuleLabelFilters string
		rawTracesReadEndpoint   string
		rawTracesWriteEndpoint  string
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
	flag.StringVar(&cfg.server.grpcListen, "grpc.listen", "",
		"The address on which the public gRPC server listens.")
	flag.StringVar(&cfg.server.listenInternal, "web.internal.listen", ":8081",
		"The address on which the internal server listens.")
	flag.StringVar(&cfg.server.healthcheckURL, "web.healthchecks.url", "http://localhost:8080",
		"The URL against which to run healthchecks.")
	flag.DurationVar(&cfg.server.readHeaderTimeout, "server.read-header-timeout", readHeaderTimeout, "Global server read header timeout.")
	flag.DurationVar(&cfg.server.readTimeout, "server.read-timeout", readTimeout, "Global server read timeout.")
	flag.DurationVar(&cfg.server.writeTimeout, "server.write-timeout", writeTimeout, "Global server read timeout.")
	flag.StringVar(&rawLogsTailEndpoint, "logs.tail.endpoint", "",
		"The endpoint against which to make tail read requests for logs.")
	flag.StringVar(&rawLogsReadEndpoint, "logs.read.endpoint", "",
		"The endpoint against which to make read requests for logs.")
	flag.StringVar(&rawLogsRulesEndpoint, "logs.rules.endpoint", "",
		"The endpoint against which to make rules requests for logs.")
	flag.BoolVar(&cfg.logs.rulesReadOnly, "logs.rules.read-only", false,
		"Allow only read-only rule requests for logs.")
	flag.StringVar(&rawLogsRuleLabelFilters, "logs.rules.label-filters", "",
		"Allow the following filters to be applied to user rules queries per tenant (e.g. tenantA:namespace,severity;tenantB:severity).")
	flag.DurationVar(&cfg.logs.upstreamWriteTimeout, "logs.write-timeout", logsMiddlewareTimeout,
		"The HTTP write timeout for proxied requests to the logs endpoint.")
	flag.StringVar(&cfg.logs.upstreamCAFile, "logs.tls.ca-file", "",
		"File containing the TLS CA against which to upstream logs servers. Leave blank to disable TLS.")
	flag.StringVar(&cfg.logs.upstreamCertFile, "logs.tls.cert-file", "",
		"File containing the TLS client certificates to authenticate against upstream logs servers. Leave blank to disable mTLS.")
	flag.StringVar(&cfg.logs.upstreamKeyFile, "logs.tls.key-file", "",
		"File containing the TLS client key to authenticate against upstream logs servers. Leave blank to disable mTLS.")
	flag.StringVar(&cfg.logs.tenantHeader, "logs.tenant-header", "X-Scope-OrgID",
		"The name of the HTTP header containing the tenant ID to forward to the logs upstream.")
	flag.StringVar(&cfg.logs.tenantLabel, "logs.rules.tenant-label", "tenant_id",
		"The name of the rules label that should hold the tenant ID in logs upstreams.")
	flag.StringVar(&rawLogsWriteEndpoint, "logs.write.endpoint", "",
		"The endpoint against which to make write requests for logs.")
	flag.StringVar(&rawMetricsReadEndpoint, "metrics.read.endpoint", "",
		"The endpoint against which to send read requests for metrics. It used as a fallback to 'query.endpoint' and 'query-range.endpoint'.")
	flag.StringVar(&rawMetricsWriteEndpoint, "metrics.write.endpoint", "",
		"The endpoint against which to make write requests for metrics.")
	flag.StringVar(&rawMetricsRulesEndpoint, "metrics.rules.endpoint", "",
		"The endpoint against which to make get requests for listing recording/alerting rules and put requests for creating/updating recording/alerting rules.")
	flag.DurationVar(&cfg.metrics.upstreamWriteTimeout, "metrics.write-timeout", metricsMiddlewareTimeout,
		"The HTTP write timeout for proxied requests to the metrics endpoint.")
	flag.StringVar(&cfg.metrics.upstreamCAFile, "metrics.tls.ca-file", "",
		"File containing the TLS CA against which to upstream metrics servers. Leave blank to disable TLS.")
	flag.StringVar(&cfg.metrics.upstreamCertFile, "metrics.tls.cert-file", "",
		"File containing the TLS client certificates to authenticate against upstream logs servers. Leave blank to disable mTLS.")
	flag.StringVar(&cfg.metrics.upstreamKeyFile, "metrics.tls.key-file", "",
		"File containing the TLS client key to authenticate against upstream metrics servers. Leave blank to disable mTLS.")
	flag.StringVar(&cfg.metrics.tenantHeader, "metrics.tenant-header", "THANOS-TENANT",
		"The name of the HTTP header containing the tenant ID to forward to the metrics upstreams.")
	flag.StringVar(&cfg.metrics.tenantLabel, "metrics.tenant-label", "tenant_id",
		"The name of the PromQL label that should hold the tenant ID in metrics upstreams.")
	flag.StringVar(&rawTracesReadEndpoint, "traces.read.endpoint", "",
		"The endpoint against which to make HTTP read requests for traces.")
	flag.StringVar(&cfg.traces.readTemplateEndpoint, "experimental.traces.read.endpoint-template", "",
		"A template replacing --read.traces.endpoint, such as http://jaeger-{tenant}-query:16686")
	flag.StringVar(&rawTracesWriteEndpoint, "traces.write.endpoint", "",
		"The endpoint against which to make gRPC write requests for traces.")
	flag.DurationVar(&cfg.traces.upstreamWriteTimeout, "traces.write-timeout", tracesMiddlewareTimeout,
		"The HTTP write timeout for proxied requests to the traces endpoint.")
	flag.StringVar(&cfg.traces.upstreamCAFile, "traces.tls.ca-file", "",
		"File containing the TLS CA against which to upstream traces servers. Leave blank to disable TLS.")
	flag.StringVar(&cfg.traces.upstreamCertFile, "traces.tls.cert-file", "",
		"File containing the TLS client certificates to authenticate against upstream logs servers. Leave blank to disable mTLS.")
	flag.StringVar(&cfg.traces.upstreamKeyFile, "traces.tls.key-file", "",
		"File containing the TLS client key to authenticate against upstream traces servers. Leave blank to disable mTLS.")
	flag.StringVar(&cfg.traces.tenantHeader, "traces.tenant-header", "X-Tenant",
		"The name of the HTTP header containing the tenant ID to forward to upstream OpenTelemetry collector.")
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
	flag.StringVar(&cfg.tls.maxVersion, "tls.max-version", "VersionTLS13",
		"Maximum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flag.StringVar(&rawTLSCipherSuites, "tls.cipher-suites", "",
		"Comma-separated list of cipher suites for the server."+
			" Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants)."+
			" If omitted, the default Go cipher suites will be used."+
			" Note that TLS 1.3 ciphersuites are not configurable.")
	flag.StringVar(&cfg.tls.clientAuthType, "tls.client-auth-type", "RequestClientCert",
		"Policy for TLS client-side authentication. Values are from ClientAuthType constants in https://pkg.go.dev/crypto/tls#ClientAuthType")
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

	if rawMetricsRulesEndpoint != "" {
		cfg.metrics.enabled = true

		metricsRulesEndpoint, err := url.ParseRequestURI(rawMetricsRulesEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--metrics.rules.endpoint %q is invalid: %w", rawMetricsRulesEndpoint, err)
		}

		cfg.metrics.rulesEndpoint = metricsRulesEndpoint
	}

	if rawLogsReadEndpoint != "" {
		cfg.logs.enabled = true

		logsReadEndpoint, err := url.ParseRequestURI(rawLogsReadEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.read.endpoint is invalid, raw %s: %w", rawLogsReadEndpoint, err)
		}

		cfg.logs.readEndpoint = logsReadEndpoint
	}

	if rawLogsRulesEndpoint != "" {
		cfg.logs.enabled = true

		logsRulesEndpoint, err := url.ParseRequestURI(rawLogsRulesEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--logs.rules.endpoint is invalid, raw %s: %w", rawLogsReadEndpoint, err)
		}

		cfg.logs.rulesEndpoint = logsRulesEndpoint
	}

	if rawLogsRuleLabelFilters != "" {
		cfg.logs.rulesLabelFilters = map[string][]string{}
		tenantFilters := strings.Split(rawLogsRuleLabelFilters, ";")

		for _, f := range tenantFilters {
			parts := strings.Split(f, ":")

			tenant := parts[0]
			cfg.logs.rulesLabelFilters[tenant] = strings.Split(parts[1], ",")
		}
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

	if cfg.traces.readTemplateEndpoint != "" {
		if rawTracesReadEndpoint != "" {
			return cfg, fmt.Errorf("only one of --traces.read.endpoint and --experimental.traces.read.endpoint-template allowed")
		}

		if !strings.Contains(cfg.traces.readTemplateEndpoint, "{tenant}") {
			fmt.Fprintf(os.Stderr,
				"--experimental.traces.read.endpoint-template does not contain '{tenant}', all tenants will use %q\n",
				cfg.traces.readTemplateEndpoint)
		}

		// After the template is expanded, will it yield a valid URL?
		_, err := tracesv1.ExpandTemplatedUpstream(cfg.traces.readTemplateEndpoint, "dummy")
		if err != nil {
			return cfg, fmt.Errorf("--experimental.traces.read.endpoint-template %q is invalid: %w", rawTracesReadEndpoint, err)
		}

		cfg.traces.enabled = true
	}

	if rawTracesReadEndpoint != "" {
		cfg.traces.enabled = true

		tracesReadEndpoint, err := url.ParseRequestURI(rawTracesReadEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--traces.read.endpoint %q is invalid: %w", rawTracesReadEndpoint, err)
		}

		cfg.traces.readEndpoint = tracesReadEndpoint
	}

	if rawTracesWriteEndpoint != "" {
		cfg.traces.enabled = true

		_, _, err := net.SplitHostPort(rawTracesWriteEndpoint)
		if err != nil {
			return cfg, fmt.Errorf("--traces.write.endpoint %q is invalid: %w", rawTracesWriteEndpoint, err)
		}

		cfg.traces.writeEndpoint = rawTracesWriteEndpoint
	}

	if cfg.traces.enabled && cfg.server.grpcListen == "" {
		return cfg, fmt.Errorf("-traces.write.endpoint is set to %q but -grpc.listen is not set", cfg.traces.writeEndpoint)
	}

	if !cfg.traces.enabled && cfg.server.grpcListen != "" {
		return cfg, fmt.Errorf("-traces.write.endpoint is not set but -grpc.listen is set to %q", cfg.server.grpcListen)
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
			httperr.PrometheusAPIError(w, "tenant not found", http.StatusInternalServerError)
			return
		}

		tenantPrefix := path.Join("/", prefix, tenant)
		http.StripPrefix(tenantPrefix, proxy.WithPrefix(tenantPrefix, next)).ServeHTTP(w, r)
	})
}

func unmarshalLegacyAuthenticatorConfig(v interface{}) (map[string]interface{}, error) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var config map[string]interface{}

	if err := json.Unmarshal(jsonBytes, &config); err != nil {
		return nil, err
	}

	return config, nil
}

func tenantAuthenticatorConfig(t *tenant) (map[string]interface{}, string, error) {
	switch {
	case t.OIDC != nil:
		return t.OIDC.config, authentication.OIDCAuthenticatorType, nil
	case t.OpenShift != nil:
		return t.OpenShift.config, authentication.OpenShiftAuthenticatorType, nil
	case t.MTLS != nil:
		return t.MTLS.config, authentication.MTLSAuthenticatorType, nil
	case t.Authenticator != nil:
		return t.Authenticator.Config, t.Authenticator.Type, nil
	default:
		return nil, "", fmt.Errorf("tenant %q must specify either an OIDC, mTLS, openshift or a supported authenticator configuration", t.Name)
	}
}

type otelErrorHandler struct {
	logger log.Logger
}

func (oh otelErrorHandler) Handle(err error) {
	level.Error(oh.logger).Log("msg", "opentelemetry", "err", err.Error())
}

func blockNonDefinedMethods() http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return http.HandlerFunc(fn)
}

// Permissions required for each gRPC method.
var gRPCRBAC = authorization.GRPCRBac{
	// "opentelemetry.proto.collector.trace.v1.TraceService/Export" requires "traces" "write" perm.
	tracesv1.TraceRoute: {
		Permission: rbac.Write,
		Resource:   "traces",
	},
	// Add trace read permission for Jaeger queries, etc.
	// Add Loki gRPC methods, etc.
}

func newGRPCServer(cfg *config, tenantHeader string, tenantIDs map[string]string, pmis authentication.GRPCMiddlewareFunc,
	authorizers map[string]rbac.Authorizer, logger log.Logger, tracesUpstreamCA []byte, tracesUpstreamCert *stdtls.Certificate) (*grpc.Server, error) {
	connOtel, err := tracesv1.NewOTelConnection(
		cfg.traces.writeEndpoint,
		tracesv1.WithLogger(logger),
		tracesv1.WithUpstreamTLS(tracesUpstreamCA, tracesUpstreamCert),
	)
	if err != nil {
		return nil, err
	}

	// Currently we only proxy TraceService/Export to OTel collectors.
	// In the future we will pass queries to Jaeger, and possibly other
	// gRPC methods for logs and metrics to different connections.
	proxiedServers := map[string]*grpc.ClientConn{
		tracesv1.TraceRoute: connOtel,
	}

	director := func(ctx context.Context, fullMethodName string) (context.Context, *grpc.ClientConn, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		outCtx := metadata.NewOutgoingContext(ctx, md.Copy())

		// Observatorium API isn't providing a generic pass-through to any methods;
		// we only pass the methods we want to expose; currently this is just TraceService/Export
		proxiedServer, ok := proxiedServers[fullMethodName]
		if ok {
			return outCtx, proxiedServer, nil
		}

		return outCtx, nil, status.Errorf(codes.Unimplemented, "Unknown method")
	}

	opts := []grpc.ServerOption{
		// Note that CustomCodec() is deprecated.  The fix for this isn't calling RegisterCodec() as suggested,
		// because the codec we need to register is also deprecated.  A better fix, if Google removes
		// the deprecated type, is to move up to the lastest https://github.com/mwitkow/grpc-proxy
		// (but see https://github.com/mwitkow/grpc-proxy/issues/55 )
		grpc.CustomCodec(grpcproxy.Codec()), // nolint: staticcheck

		grpc.UnknownServiceHandler(grpcproxy.TransparentHandler(director)),
		grpc.ChainStreamInterceptor(
			authentication.WithGRPCTenantHeader(tenantHeader, tenantIDs, logger),
			authentication.WithGRPCAccessToken(),
			authentication.WithGRPCTenantInterceptors(logger, pmis),
			auth.StreamServerInterceptor(
				authorization.WithGRPCAuthorizers(authorizers, gRPCRBAC, logger)),
		),
	}

	if cfg.tls.serverCertFile != "" {
		serverCert, err := credentials.NewServerTLSFromFile(cfg.tls.serverCertFile, cfg.tls.serverKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create gRPC cert: %v\n", err)
			return nil, err
		}

		opts = append(opts, grpc.Creds(serverCert))
	}

	gs := grpc.NewServer(opts...)

	return gs, nil
}

type groupHandler struct {
	group   string
	handler string
}

var legacyMetricsGroup = map[string]groupHandler{
	metricslegacy.QueryRoute:      {"metricslegacy", "query"},
	metricslegacy.QueryRangeRoute: {"metricslegacy", "query_range"},
}

var metricsV1Group = map[string]groupHandler{
	metricsv1.UIRoute:          {"metricsv1", "ui"},
	metricsv1.QueryRoute:       {"metricsv1", "query"},
	metricsv1.QueryRangeRoute:  {"metricsv1", "query_range"},
	metricsv1.SeriesRoute:      {"metricsv1", "series"},
	metricsv1.LabelNamesRoute:  {"metricsv1", "labels"},
	metricsv1.LabelValuesRoute: {"metricsv1", "labelvalues"},
	metricsv1.ReceiveRoute:     {"metricsv1", "receive"},
	metricsv1.RulesRoute:       {"metricsv1", "rules"},
	metricsv1.RulesRawRoute:    {"metricsv1", "rules-raw"},
}

func chiLabelParser(r *http.Request) prometheus.Labels {
	extraLabels := prometheus.Labels{
		"handler": "unknown",
		"group":   "unknown",
	}

	routePattern := chi.RouteContext(r.Context()).RoutePattern()
	tenant, ok := authentication.GetTenant(r.Context())
	if !ok {
		return extraLabels
	}

	var groupHandler map[string]groupHandler
	switch routePattern {
	case "/api/metrics/v1/{tenant}/*":
		groupHandler = metricsV1Group
	case "/api/v1/{tenant}/*":
		groupHandler = legacyMetricsGroup
	}

	strippedPath := strings.Split(r.URL.Path, tenant)
	if len(strippedPath) != 2 {
		return extraLabels
	}

	gh, ok := groupHandler[strippedPath[1]]
	if ok {
		extraLabels = prometheus.Labels{
			"group":   gh.group,
			"handler": gh.handler,
		}
	}
	return extraLabels
}
