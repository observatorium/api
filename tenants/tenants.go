package tenants

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"runtime"
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

type Config struct {
	LogLevel  string
	LogFormat string

	RBACConfigPath    string
	TenantsConfigPath string

	Debug           debugConfig
	Server          serverConfig
	TLS             tlsConfig
	Metrics         metricsConfig
	Logs            logsConfig
	Middleware      middlewareConfig
	InternalTracing internalTracingConfig
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

type metricsConfig struct {
	ReadEndpoint  *url.URL
	WriteEndpoint *url.URL
	TenantHeader  string
	TenantLabel   string
}

type logsConfig struct {
	ReadEndpoint  *url.URL
	WriteEndpoint *url.URL
	TailEndpoint  *url.URL
	TenantHeader  string
	// enable logs at least one {read,write,tail}Endpoint} is provided.
	Enabled bool
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
		Query      string   `json:"query"`
		Paths      []string `json:"paths"`
		URL        string   `json:"url"`
		authorizer rbac.Authorizer
	} `json:"opa"`
	RateLimits []*struct {
		Endpoint string   `json:"endpoint"`
		Limit    int      `json:"limit"`
		Window   duration `json:"window"`
	} `json:"rateLimits"`
}

type tenantsConfig struct {
	Tenants            []*tenant `json:"tenants"`
	rateLimitClient    *ratelimit.Client
	authorizer         rbac.Authorizer
	ins                signalhttp.HandlerInstrumenter
	reg                *prometheus.Registry
	retryCounterMetric *prometheus.CounterVec
	logger             log.Logger
}

func Run(cfg *Config) {
	// Load all the command line configuration into tenantsConfig struct.
	tCfg := loadTenantConfigs(cfg)

	// Onboard tenants.
	listenAndServeTenants(cfg, &tCfg)
	stdlog.Fatalf("could not start Observatorium API server, exiting ...")
}

//nolint:funlen
func listenAndServeTenants(cfg *Config, tCfg *tenantsConfig) {
	defer level.Info(tCfg.logger).Log("msg", "exiting")

	tp, closer, err := tracing.InitTracer(
		cfg.InternalTracing.ServiceName,
		cfg.InternalTracing.Endpoint,
		cfg.InternalTracing.EndpointType,
		cfg.InternalTracing.SamplingFraction,
	)
	defer closer()

	if err != nil {
		level.Error(tCfg.logger).Log("msg", "initialize tracer:", "err", err)
		return
	}

	// Register for capturing retry metrics.
	err = registerTenantRetryMetric(tCfg)
	if err != nil {
		level.Error(tCfg.logger).Log("msg", "initialize Prometheus registry:", "err", err)
		return
	}

	otel.SetErrorHandler(otelErrorHandler{logger: tCfg.logger})

	debug := os.Getenv("DEBUG") != ""
	if debug {
		runtime.SetMutexProfileFraction(cfg.Debug.MutexProfileFraction)
		runtime.SetBlockProfileRate(cfg.Debug.BlockProfileRate)
	}
	// maxprocs will automate adjustment by using cgroups info about cpu limit if it set as value for runtime.GOMAXPROCS.
	undo, err := maxprocs.Set(maxprocs.Logger(func(template string, args ...interface{}) {}))
	if err != nil {
		level.Error(tCfg.logger).Log("msg", "failed to set GOMAXPROCS:", "err", err)
	}

	defer undo()

	var g run.Group
	{
		sig := make(chan os.Signal, 1)
		g.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			level.Info(tCfg.logger).Log("msg", "caught interrupt")
			return nil
		}, func(_ error) {
			close(sig)
		})
	}
	{
		r := chi.NewRouter()
		commonMiddlewares(r, cfg, tCfg)
		for _, t := range tCfg.Tenants {
			if t == nil {
				continue
			}
			go newTenant(cfg, tCfg, r, t)
		}
		tlsConfig, err := tls.NewServerConfig(
			log.With(tCfg.logger, "protocol", "HTTP"),
			cfg.TLS.ServerCertFile,
			cfg.TLS.ServerKeyFile,
			cfg.TLS.MinVersion,
			cfg.TLS.CipherSuites,
		)
		if err != nil {
			level.Error(tCfg.logger).Log("msg", "failed to initialize tls config:", "err", err)
			return
		}
		if tlsConfig != nil {
			r, err := rbacproxytls.NewCertReloader(
				cfg.TLS.ServerCertFile,
				cfg.TLS.ServerKeyFile,
				cfg.TLS.ReloadInterval,
			)
			if err != nil {
				level.Error(tCfg.logger).Log("msg", "failed to initialize certificate reloader:", "err", err)
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
			Addr:         cfg.Server.Listen,
			Handler:      otelhttp.NewHandler(r, "api", otelhttp.WithTracerProvider(tp)),
			TLSConfig:    tlsConfig,
			ReadTimeout:  readTimeout,  // best set per handler.
			WriteTimeout: writeTimeout, // best set per handler.
		}
		g.Add(func() error {
			level.Info(tCfg.logger).Log("msg", "starting the HTTP server", "address", cfg.Server.Listen)
			if tlsConfig != nil {
				return s.ListenAndServeTLS("", "")
			}

			return s.ListenAndServe()
		}, func(err error) {
			// gracePeriod is duration the server gracefully shuts down.
			ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
			defer cancel()
			level.Info(tCfg.logger).Log("msg", "shutting down the HTTP server")
			_ = s.Shutdown(ctx)
		})
	}
	{
		healthchecks := commonHealthChecks(cfg, tCfg)
		s := setupInternalServer(cfg, tCfg, *healthchecks)
		g.Add(func() error {
			level.Info(tCfg.logger).Log("msg", "starting internal HTTP server", "address", s.Addr)
			return s.ListenAndServe()
		}, func(err error) {
			_ = s.Shutdown(context.Background())
		})
	}

	if err := g.Run(); err != nil {
		return
	}
}

// commonHealthChecks returns handler for common healthchecks across all the tenants.
func commonHealthChecks(cfg *Config, tCfg *tenantsConfig) *healthcheck.Handler {
	healthchecks := healthcheck.NewMetricsHandler(healthcheck.NewHandler(), tCfg.reg)

	if cfg.Server.HealthcheckURL != "" {
		t := (http.DefaultTransport).(*http.Transport).Clone()
		t.TLSClientConfig = &stdtls.Config{
			ServerName: cfg.TLS.HealthchecksServerName,
		}

		if cfg.TLS.HealthchecksServerCAFile != "" {
			caCert, err := ioutil.ReadFile(cfg.TLS.HealthchecksServerCAFile)
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
				cfg.Server.HealthcheckURL,
				http.MethodGet,
				http.StatusNotFound,
				time.Second,
			),
		)
	}

	return &healthchecks
}

// Apply common middlewares across all the tenants.
func commonMiddlewares(r *chi.Mux, cfg *Config, tCfg *tenantsConfig) {
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(middlewareTimeout)) // best set per handler.
	// With default value of zero backlog concurrent requests crossing a rate-limit result in non-200 HTTP response.
	r.Use(middleware.ThrottleBacklog(cfg.Middleware.ConcurrentRequestLimit,
		cfg.Middleware.BackLogLimitConcurrentRequests, cfg.Middleware.BackLogDurationConcurrentRequests))
	r.Use(server.Logger(tCfg.logger))
}

// Create internal server.
func setupInternalServer(cfg *Config, tCfg *tenantsConfig, healthchecks healthcheck.Handler) *http.Server {
	h := internalserver.NewHandler(
		internalserver.WithName("Internal - Observatorium API"),
		internalserver.WithHealthchecks(healthchecks),
		internalserver.WithPrometheusRegistry(tCfg.reg),
		internalserver.WithPProf(),
	)

	s := http.Server{
		Addr:    cfg.Server.ListenInternal,
		Handler: h,
	}

	return &s
}

// Load RBAC config information from rbac.yaml.
func loadRBACConfig(cfg Config) (rbac.Authorizer, error) {
	f, err := os.Open(cfg.RBACConfigPath)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	authorizer, err := rbac.Parse(f)
	if err != nil {
		return nil, err
	}

	return authorizer, nil
}

// Load tenant config information from tenants.yaml.
func loadTenantConfigs(cfg *Config) tenantsConfig {
	tCfg := tenantsConfig{}
	tCfg.logger = logger.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.Debug.Name)

	f, err := ioutil.ReadFile(cfg.TenantsConfigPath)
	if err != nil {
		stdlog.Fatalf("cannot read tenant configuration file from path %q: %v", cfg.TenantsConfigPath, err)
	}

	if err := yaml.Unmarshal(f, &tCfg); err != nil {
		stdlog.Fatalf("unable to read tenant YAML: %v", err)
	}

	skip := level.Warn(log.With(tCfg.logger, "msg", "skipping invalid tenant"))

	for _, t := range tCfg.Tenants {
		err = loadOIDCConf(tCfg.logger, t)
		if err != nil {
			skip.Log("tenant", t.Name, "err", err)
		}

		err = loadMTLSConf(tCfg.logger, t)
		if err != nil {
			skip.Log("tenant", t.Name, "err", err)
		}

		err = newAuthorizer(tCfg.logger, t)
		if err != nil {
			skip.Log("tenant", t.Name, "err", err)
		}
	}

	// Load RBAC config information from rbac.yaml.
	tCfg.authorizer, err = loadRBACConfig(*cfg)
	if err != nil {
		stdlog.Fatalf("unable to read RBAC YAML: %v", err)
		return tCfg
	}

	tCfg.reg = prometheus.NewRegistry()
	tCfg.reg.MustRegister(
		version.NewCollector("observatorium"),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	if cfg.Middleware.RateLimiterAddress != "" {
		ctx, cancel := context.WithTimeout(context.Background(), grpcDialTimeout)
		defer cancel()

		tCfg.rateLimitClient = ratelimit.NewClient(tCfg.reg)
		if err := tCfg.rateLimitClient.Dial(ctx, cfg.Middleware.RateLimiterAddress); err != nil {
			stdlog.Fatal(err)
		}
	}

	tCfg.ins = signalhttp.NewHandlerInstrumenter(tCfg.reg, []string{"group", "handler"})

	return tCfg
}

// Create authorizer for a tenant.
func newAuthorizer(logger log.Logger, t *tenant) error {
	skip := level.Warn(log.With(logger, "msg", "skipping invalid tenant"))

	if t.OPA != nil {
		if t.OPA.URL != "" {
			u, err := url.Parse(t.OPA.URL)
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse OPA URL: %v", err))

				return err
			}

			t.OPA.authorizer = opa.NewRESTAuthorizer(u, opa.LoggerOption(log.With(logger, "tenant", t.Name)))
		} else {
			a, err := opa.NewInProcessAuthorizer(t.OPA.Query, t.OPA.Paths, opa.LoggerOption(log.With(logger, "tenant", t.Name)))
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to create in-process OPA authorizer: %v", err))

				return err
			}
			t.OPA.authorizer = a
		}
	}

	return nil
}

// Load MTLS auth information for a tenant.
func loadMTLSConf(logger log.Logger, t *tenant) error {
	var err error

	skip := level.Warn(log.With(logger, "msg", "skipping invalid tenant"))

	if t.MTLS != nil {
		if t.MTLS.CAPath != "" {
			t.MTLS.RawCA, err = ioutil.ReadFile(t.MTLS.CAPath)

			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("cannot read CA certificate file for tenant %q: %v", t.Name, err))

				return err
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

				break
			}

			cert, err = x509.ParseCertificate(block.Bytes)

			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse CA certificate: %v", err))

				break
			}

			t.MTLS.cas = append(t.MTLS.cas, cert)

			if len(rest) == 0 {
				break
			}
		}
	}

	return nil
}

// Load OIDC auth information for a tenant.
func loadOIDCConf(logger log.Logger, t *tenant) error {
	skip := level.Warn(log.With(logger, "msg", "skipping invalid tenant"))

	var err error

	if t.OIDC != nil {
		if t.OIDC.IssuerCAPath != "" {
			t.OIDC.IssuerRawCA, err = ioutil.ReadFile(t.OIDC.IssuerCAPath)
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("cannot read issuer CA certificate file for tenant : %q %v", t.Name, err))

				return err
			}
		}

		if len(t.OIDC.IssuerRawCA) != 0 {
			block, _ := pem.Decode(t.OIDC.IssuerRawCA)

			if block == nil {
				skip.Log("tenant", t.Name, "err", "failed to parse issuer CA certificate PEM")

				return err
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse issuer certificate: %v", err))

				return err
			}

			t.OIDC.issuerCA = cert
		}
	}

	return nil
}

// Onboard a tenant.
func newTenant(cfg *Config, tCfg *tenantsConfig, r *chi.Mux, t *tenant) {
	retryCount := 0

	for {
		// Calculate wait time before rerying a failed tenant registration.
		waitTime := expBackOffWaitTime(retryCount)
		time.Sleep(time.Duration(waitTime) * time.Millisecond)

		rateLimits := tenantRateLimits(tCfg.logger, t)

		oidcConf, mTLSConf, err := tennatAuthN(t)
		if err != nil {
			level.Error(tCfg.logger).Log("msg", "tenant must specify either an OIDC or an mTLS configuration", t.Name, err)
			tCfg.retryCounterMetric.With(prometheus.Labels{"tenant": t.Name}).Inc()
			retryCount++

			continue
		}

		var (
			authN       authentication.Middleware
			authZ       rbac.Authorizer
			oidcHandler http.Handler
		)

		if len(oidcConf.Tenant) > 0 {
			// Create OIDC middleware for a tenant.
			oidcHandler, authN, err = authentication.NewOIDC(tCfg.logger, "/oidc/"+t.Name, *oidcConf)
			if err != nil {
				level.Error(tCfg.logger).Log("msg", "tenant failed to register. retrying ..", t.Name, err)
				tCfg.retryCounterMetric.With(prometheus.Labels{"tenant": t.Name}).Inc()
				retryCount++

				continue
			}

			r.Mount("/oidc/"+t.Name, oidcHandler)
		}

		if len(mTLSConf.Tenant) > 0 {
			mTLSMiddleware, err := authentication.NewMTLS(*mTLSConf)
			if err != nil {
				level.Info(tCfg.logger).Log("msg", "err", err.Error(), "tenant", t.Name)
			} else {
				authN = mTLSMiddleware
			}
		}

		if t.OPA != nil {
			authZ = t.OPA.authorizer
		} else {
			authZ = tCfg.authorizer
		}

		if authZ == nil {
			level.Error(tCfg.logger).Log("msg", "invalid authorization for tenant", t.Name)
			tCfg.retryCounterMetric.With(prometheus.Labels{"tenant": t.Name}).Inc()
			retryCount++

			continue
		}

		r.HandleFunc("/{tenant}", func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				w.WriteHeader(http.StatusNotFound)

				return
			}
			http.Redirect(w, r, path.Join("/api/metrics/v1/", tenant, "graph"), http.StatusMovedPermanently)
		})

		// Metrics
		r.Group(func(r chi.Router) {
			r.Use(authentication.WithTenant(t.Name, t.ID))
			r.Use(authN)
			r.Use(authentication.WithTenantHeader(cfg.Metrics.TenantHeader, t.ID))

			if tCfg.rateLimitClient != nil {
				r.Use(ratelimit.WithSharedRateLimiter(tCfg.logger, tCfg.rateLimitClient, rateLimits...))
			} else {
				r.Use(ratelimit.WithLocalRateLimiter(rateLimits...))
			}

			r.Mount("/api/v1/"+t.Name, metricsLegacyHandler(cfg, tCfg, authZ))
			r.Mount("/api/metrics/v1/"+t.Name, stripTenantPrefix("/api/metrics/v1", metricsHandler(cfg, tCfg, authZ)))
		})
		// Logs
		if cfg.Logs.Enabled {
			r.Group(func(r chi.Router) {
				r.Use(authentication.WithTenant(t.Name, t.ID))
				r.Use(authN)
				r.Use(authentication.WithTenantHeader(cfg.Logs.TenantHeader, t.ID))
				r.Mount("/api/logs/v1/"+t.Name, stripTenantPrefix("/api/logs/v1", logsHandler(cfg, tCfg, authZ)))
			})
		}

		level.Info(tCfg.logger).Log("msg", "tenant registration is successful :", t.Name)

		break
	}
}

func registerTenantRetryMetric(tCfg *tenantsConfig) error {
	retryMetric := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tenant_onboarding_attempts_total",
			Help: "Number of tenant onboarding attempts.",
		},
		[]string{"tenant"},
	)

	err := tCfg.reg.Register(retryMetric)
	if err != nil {
		level.Info(tCfg.logger).Log("msg", "duplicate registration of metric", "error", err)
		return err
	}

	tCfg.retryCounterMetric = retryMetric

	return nil
}

// metricsLegacyHandler creates handler for legacyMetrics V1 API.
func metricsLegacyHandler(cfg *Config, tCfg *tenantsConfig, authZ rbac.Authorizer) http.Handler {
	return metricslegacy.NewHandler(
		cfg.Metrics.ReadEndpoint,
		metricslegacy.Logger(tCfg.logger),
		metricslegacy.Registry(tCfg.reg),
		metricslegacy.HandlerInstrumenter(tCfg.ins),
		metricslegacy.SpanRoutePrefix("/api/v1/{tenant}"),
		metricslegacy.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")),
		metricslegacy.ReadMiddleware(metricsv1.WithEnforceTenantLabel(cfg.Metrics.TenantLabel)),
		metricslegacy.UIMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")))
}

// metricsHandler creates handler for Metrics V1 API.
func metricsHandler(cfg *Config, tCfg *tenantsConfig, authZ rbac.Authorizer) http.Handler {
	return metricsv1.NewHandler(
		cfg.Metrics.ReadEndpoint,
		cfg.Metrics.WriteEndpoint,
		metricsv1.Logger(tCfg.logger),
		metricsv1.Registry(tCfg.reg),
		metricsv1.HandlerInstrumenter(tCfg.ins),
		metricsv1.SpanRoutePrefix("/api/metrics/v1/{tenant}"),
		metricsv1.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")),
		metricsv1.ReadMiddleware(metricsv1.WithEnforceTenantLabel(cfg.Metrics.TenantLabel)),
		metricsv1.WriteMiddleware(authorization.WithAuthorizers(authZ, rbac.Write, "metrics")),
	)
}

// logsHandler creates handler for Logs V1 API.
func logsHandler(cfg *Config, tCfg *tenantsConfig, authZ rbac.Authorizer) http.Handler {
	return logsv1.NewHandler(
		cfg.Logs.ReadEndpoint,
		cfg.Logs.TailEndpoint,
		cfg.Logs.WriteEndpoint,
		logsv1.Logger(tCfg.logger),
		logsv1.Registry(tCfg.reg),
		logsv1.HandlerInstrumenter(tCfg.ins),
		logsv1.SpanRoutePrefix("/api/logs/v1/{tenant}"),
		logsv1.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "logs")),
		logsv1.WriteMiddleware(authorization.WithAuthorizers(authZ, rbac.Write, "logs")))
}

// expBackOffWaitTime calculate exponential backoff wait time, used for retrying failed tenant onboarding.
func expBackOffWaitTime(retryCount int) uint64 {
	if retryCount == 0 {
		return 0
	}

	return uint64(math.Pow(2, float64(retryCount)))
}

// Create authentication middlware for a tenant.
func tennatAuthN(t *tenant) (*authentication.TenantOIDCConfig, *authentication.MTLSConfig, error) {
	oidcConf := authentication.TenantOIDCConfig{}
	mTLSConf := authentication.MTLSConfig{}

	switch {
	case t.OIDC != nil:
		oidcConf = authentication.TenantOIDCConfig{
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
		}

	case t.MTLS != nil:
		mTLSConf = authentication.MTLSConfig{
			Tenant: t.Name,
			CAs:    t.MTLS.cas,
		}
	default:
		stdlog.Fatalf("tenant %q must specify either an OIDC or an mTLS configuration", t.Name)
		err := errors.New("tenant must specify either an OIDC or an mTLS configuration : " + t.Name)

		return &oidcConf, &mTLSConf, err
	}

	return &oidcConf, &mTLSConf, nil
}

// Populate rateLimit configuration for a tenant.
func tenantRateLimits(logger log.Logger, t *tenant) []ratelimit.Config {
	rateLimits := []ratelimit.Config{}

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

	return rateLimits
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
