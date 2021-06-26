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
	logsv1 "github.com/observatorium/api/api/logs/v1"
	metricslegacy "github.com/observatorium/api/api/metrics/legacy"
	metricsv1 "github.com/observatorium/api/api/metrics/v1"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/logger"

	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/version"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.uber.org/automaxprocs/maxprocs"

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

	debug                        debugConfig
	server                       serverConfig
	tls                          tlsConfig
	metrics                      metricsConfig
	logs                         logsConfig
	middleware                   middlewareConfig
	internalTracing              internalTracingConfig
	tenantRegistrationRetryCount int
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

	healthchecksServerCAFile string
	healthchecksServerName   string
}

type metricsConfig struct {
	readEndpoint  *url.URL
	writeEndpoint *url.URL
	tenantHeader  string
	tenantLabel   string
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
	Tenants         []*tenant `json:"tenants"`
	rateLimitClient *ratelimit.Client
	authorizer      rbac.Authorizer
	ins             signalhttp.HandlerInstrumenter
	reg             *prometheus.Registry
	logger          log.Logger
}

//nolint:funlen,gocyclo,gocognit
func main() {
	cfg, err := parseFlags()
	if err != nil {
		stdlog.Fatalf("parse flag: %v", err)
	}

	tCfg := tenantsConfig{}
	tCfg.logger = logger.NewLogger(cfg.logLevel, cfg.logFormat, cfg.debug.name)

	defer level.Info(tCfg.logger).Log("msg", "exiting")

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

	otel.SetErrorHandler(otelErrorHandler{logger: tCfg.logger})

	// Load tenant config information from tenants.yaml.
	loadTenantConfigs(&cfg, &tCfg)

	// Load RBAC config information from rbac.yaml.
	tCfg.authorizer, err = loadRBACConfig(cfg)
	if err != nil {
		stdlog.Fatalf("unable to read RBAC YAML: %v", err)
		return
	}

	tCfg.reg = prometheus.NewRegistry()

	tCfg.reg.MustRegister(
		version.NewCollector("observatorium"),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	if cfg.middleware.rateLimiterAddress != "" {
		ctx, cancel := context.WithTimeout(context.Background(), grpcDialTimeout)
		defer cancel()

		tCfg.rateLimitClient = ratelimit.NewClient(tCfg.reg)
		if err := tCfg.rateLimitClient.Dial(ctx, cfg.middleware.rateLimiterAddress); err != nil {
			stdlog.Fatal(err)
		}
	}

	healthchecks := healthcheck.NewMetricsHandler(healthcheck.NewHandler(), tCfg.reg)

	debug := os.Getenv("DEBUG") != ""
	if debug {
		runtime.SetMutexProfileFraction(cfg.debug.mutexProfileFraction)
		runtime.SetBlockProfileRate(cfg.debug.blockProfileRate)
	}

	// Running in container with limits but with empty/wrong value of GOMAXPROCS env var could lead to throttling by cpu
	// maxprocs will automate adjustment by using cgroups info about cpu limit if it set as value for runtime.GOMAXPROCS
	undo, err := maxprocs.Set(maxprocs.Logger(func(template string, args ...interface{}) {
		level.Debug(tCfg.logger).Log("msg", fmt.Sprintf(template, args))
	}))
	if err != nil {
		level.Error(tCfg.logger).Log("msg", "failed to set GOMAXPROCS:", "err", err)
	}

	defer undo()

	level.Info(tCfg.logger).Log("msg", "starting observatorium")

	var g run.Group
	{
		// Signal channels must be buffered.
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
		r.Use(server.Logger(tCfg.logger))

		tCfg.ins = signalhttp.NewHandlerInstrumenter(tCfg.reg, []string{"group", "handler"})

		// tenantsCfg contain all the yaml content from tenants.yaml.
		for _, t := range tCfg.Tenants {
			if t == nil {
				continue
			}
			go newTenant(&cfg, &tCfg, r, t)
		}

		tlsConfig, err := tls.NewServerConfig(
			log.With(tCfg.logger, "protocol", "HTTP"),
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
			level.Info(tCfg.logger).Log("msg", "starting the HTTP server", "address", cfg.server.listen)

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

			level.Info(tCfg.logger).Log("msg", "shutting down the HTTP server")
			_ = s.Shutdown(ctx)
		})
	}
	{
		h := internalserver.NewHandler(
			internalserver.WithName("Internal - Observatorium API"),
			internalserver.WithHealthchecks(healthchecks),
			internalserver.WithPrometheusRegistry(tCfg.reg),
			internalserver.WithPProf(),
		)

		s := http.Server{
			Addr:    cfg.server.listenInternal,
			Handler: h,
		}

		g.Add(func() error {
			level.Info(tCfg.logger).Log("msg", "starting internal HTTP server", "address", s.Addr)
			return s.ListenAndServe()
		}, func(err error) {
			_ = s.Shutdown(context.Background())
		})
	}

	if err := g.Run(); err != nil {
		stdlog.Fatal(err)
	}
}

// Load RBAC config information from rbac.yaml.
func loadRBACConfig(cfg config) (rbac.Authorizer, error) {
	f, err := os.Open(cfg.rbacConfigPath)
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
func loadTenantConfigs(cfg *config, tCfg *tenantsConfig) {
	f, err := ioutil.ReadFile(cfg.tenantsConfigPath)
	if err != nil {
		stdlog.Fatalf("cannot read tenant configuration file from path %q: %v", cfg.tenantsConfigPath, err)
	}

	if err := yaml.Unmarshal(f, &tCfg); err != nil {
		stdlog.Fatalf("unable to read tenant YAML: %v", err)
	}

	skip := level.Warn(log.With(tCfg.logger, "msg", "skipping invalid tenant"))

	for _, t := range tCfg.Tenants {
		err = loadOIDCConf(tCfg, t)
		if err != nil {
			skip.Log("tenant", t.Name, "err", err)
		}

		err = loadMTLSConf(tCfg, t)
		if err != nil {
			skip.Log("tenant", t.Name, "err", err)
		}

		err = newAuthorizer(tCfg, t)
		if err != nil {
			skip.Log("tenant", t.Name, "err", err)
		}
	}
}

func newAuthorizer(tCfg *tenantsConfig, t *tenant) error {
	skip := level.Warn(log.With(tCfg.logger, "msg", "skipping invalid tenant"))

	if t.OPA != nil {
		if t.OPA.URL != "" {
			u, err := url.Parse(t.OPA.URL)
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse OPA URL: %v", err))

				t = nil

				return err
			}

			t.OPA.authorizer = opa.NewRESTAuthorizer(u, opa.LoggerOption(log.With(tCfg.logger, "tenant", t.Name)))
		} else {
			a, err := opa.NewInProcessAuthorizer(t.OPA.Query, t.OPA.Paths, opa.LoggerOption(log.With(tCfg.logger, "tenant", t.Name)))
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to create in-process OPA authorizer: %v", err))

				t = nil

				return err
			}
			t.OPA.authorizer = a
		}
	}

	return nil
}

func loadMTLSConf(tCfg *tenantsConfig, t *tenant) error {
	var err error

	skip := level.Warn(log.With(tCfg.logger, "msg", "skipping invalid tenant"))

	if t.MTLS != nil {
		if t.MTLS.CAPath != "" {
			t.MTLS.RawCA, err = ioutil.ReadFile(t.MTLS.CAPath)

			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("cannot read CA certificate file from path %q: %v", t.OIDC.IssuerCAPath, err))

				t = nil

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

				t = nil

				break
			}

			cert, err = x509.ParseCertificate(block.Bytes)

			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse CA certificate: %v", err))

				t = nil

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

func loadOIDCConf(tCfg *tenantsConfig, t *tenant) error {
	skip := level.Warn(log.With(tCfg.logger, "msg", "skipping invalid tenant"))

	var err error

	if t.OIDC != nil {
		if t.OIDC.IssuerCAPath != "" {
			t.OIDC.IssuerRawCA, err = ioutil.ReadFile(t.OIDC.IssuerCAPath)
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("cannot read issuer CA certificate file from path %q: %v", t.OIDC.IssuerCAPath, err))
				t = nil

				return err
			}
		}

		if len(t.OIDC.IssuerRawCA) != 0 {
			block, _ := pem.Decode(t.OIDC.IssuerRawCA)

			if block == nil {
				skip.Log("tenant", t.Name, "err", "failed to parse issuer CA certificate PEM")
				t = nil

				return err
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				skip.Log("tenant", t.Name, "err", fmt.Sprintf("failed to parse issuer certificate: %v", err))
				t = nil

				return err
			}

			t.OIDC.issuerCA = cert
		}
	}

	return nil
}

// Onboard a tenant.
func newTenant(cfg *config, tCfg *tenantsConfig, r *chi.Mux, t *tenant) {
	rateLimits := tenantRateLimits(tCfg, t)

	oidcConf, mTLSConf, err := tennatAuthN(t)
	if err != nil {
		level.Error(tCfg.logger).Log("msg", "tenant must specify either an OIDC or an mTLS configuration", t.Name, err)
		return
	}

	var (
		authN authentication.Middleware
		authZ rbac.Authorizer
	)

	level.Info(tCfg.logger).Log("msg", "adding a tenant: ", "tenant", t.Name)
	oidcHandler, oidcTenantMiddleware, err := createOIDCMiddlware(cfg, tCfg, t.Name, oidcConf)

	if err != nil {
		level.Error(tCfg.logger).Log("msg", "tenant  registration is marked as failure:", t.Name, err)
	}

	level.Info(tCfg.logger).Log("msg", "tenant registration is successful :", t.Name)

	if oidcTenantMiddleware != nil {
		authN = oidcTenantMiddleware
	}

	mTLSMiddleware := authentication.NewMTLS(mTLSConf)

	if len(mTLSConf.CAs) > 0 {
		authN = mTLSMiddleware
	}

	if t.OPA != nil {
		authZ = t.OPA.authorizer
	} else {
		authZ = tCfg.authorizer
	}

	if oidcTenantMiddleware != nil {
		r.Mount("/oidc/"+t.Name, oidcHandler)
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
		r.Use(authentication.WithTenantID(t.Name, t.ID))
		r.Use(authentication.WithTenant)

		r.Use(authN)
		r.Use(authentication.WithTenantHeader(cfg.metrics.tenantHeader, t.ID))

		if tCfg.rateLimitClient != nil {
			r.Use(ratelimit.WithSharedRateLimiter(tCfg.logger, tCfg.rateLimitClient, rateLimits...))
		} else {
			r.Use(ratelimit.WithLocalRateLimiter(rateLimits...))
		}

		r.Mount("/api/v1/"+t.Name,
			metricslegacy.NewHandler(
				cfg.metrics.readEndpoint,
				metricslegacy.Logger(tCfg.logger),
				metricslegacy.Registry(tCfg.reg),
				metricslegacy.HandlerInstrumenter(tCfg.ins),
				metricslegacy.SpanRoutePrefix("/api/v1/{tenant}"),
				metricslegacy.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")),
				metricslegacy.ReadMiddleware(authorization.WithEnforceTenantLabel(cfg.metrics.tenantLabel)),
				metricslegacy.UIMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics"))),
		)
		r.Mount("/api/metrics/v1/"+t.Name,
			stripTenantPrefix("/api/metrics/v1",
				metricsv1.NewHandler(
					cfg.metrics.readEndpoint,
					cfg.metrics.writeEndpoint,
					metricsv1.Logger(tCfg.logger),
					metricsv1.Registry(tCfg.reg),
					metricsv1.HandlerInstrumenter(tCfg.ins),
					metricsv1.SpanRoutePrefix("/api/metrics/v1/{tenant}"),
					metricsv1.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")),
					metricsv1.ReadMiddleware(authorization.WithEnforceTenantLabel(cfg.metrics.tenantLabel)),
					metricsv1.WriteMiddleware(authorization.WithAuthorizers(authZ, rbac.Write, "metrics")),
				),
			),
		)
	})

	// Logs
	if cfg.logs.enabled {
		r.Group(func(r chi.Router) {
			r.Use(authentication.WithTenantID(t.Name, t.ID))
			r.Use(authentication.WithTenant)

			r.Use(authN)
			r.Use(authentication.WithTenantHeader(cfg.logs.tenantHeader, t.ID))

			r.Mount("/api/logs/v1/"+t.Name,
				stripTenantPrefix("/api/logs/v1",
					logsv1.NewHandler(
						cfg.logs.readEndpoint,
						cfg.logs.tailEndpoint,
						cfg.logs.writeEndpoint,
						logsv1.Logger(tCfg.logger),
						logsv1.Registry(tCfg.reg),
						logsv1.HandlerInstrumenter(tCfg.ins),
						logsv1.SpanRoutePrefix("/api/logs/v1/{tenant}"),
						logsv1.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "logs")),
						logsv1.WriteMiddleware(authorization.WithAuthorizers(authZ, rbac.Write, "logs")),
					),
				),
			)
		})
	}
}

func tennatAuthN(t *tenant) (authentication.TenantOIDCConfig, authentication.MTLSConfig, error) {
	var (
		oidcConf authentication.TenantOIDCConfig
		mTLSConf authentication.MTLSConfig
	)

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

		return authentication.TenantOIDCConfig{}, authentication.MTLSConfig{}, err
	}

	return oidcConf, mTLSConf, nil
}

func tenantRateLimits(tCfg *tenantsConfig, t *tenant) []ratelimit.Config {
	rateLimits := []ratelimit.Config{}

	if t.RateLimits != nil {
		for _, rl := range t.RateLimits {
			matcher, err := regexp.Compile(rl.Endpoint)
			if err != nil {
				level.Warn(tCfg.logger).Log("msg", "failed to compile matcher for rate limiter", "err", err)
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

// Create OIDC middleware for a tenant.
func createOIDCMiddlware(cfg *config, tCfg *tenantsConfig,
	tenantName string, oidcConf authentication.TenantOIDCConfig) (http.Handler, authentication.Middleware, error) {
	var (
		oidcHandler          http.Handler
		oidcTenantMiddleware authentication.Middleware
		err                  error
	)

	for i := 1; i < cfg.tenantRegistrationRetryCount; i++ {
		oidcHandler, oidcTenantMiddleware, err = authentication.NewOIDC(tCfg.logger, "/oidc/"+tenantName, oidcConf)
		if err != nil {
			level.Error(tCfg.logger).Log("msg", "tenant  failed to register. retrying ..", tenantName, err)
			continue
		}
	}

	if oidcTenantMiddleware == nil {
		return nil, nil, err
	}

	return oidcHandler, oidcTenantMiddleware, nil
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
	flag.IntVar(&cfg.tenantRegistrationRetryCount, "tenants.registration-retry-count", 3,
		"The number of retries for tenant auth registration.")
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

	metricsReadEndpoint, err := url.ParseRequestURI(rawMetricsReadEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.read.endpoint %q is invalid: %w", rawMetricsReadEndpoint, err)
	}

	cfg.metrics.readEndpoint = metricsReadEndpoint

	metricsWriteEndpoint, err := url.ParseRequestURI(rawMetricsWriteEndpoint)
	if err != nil {
		return cfg, fmt.Errorf("--metrics.write.endpoint %q is invalid: %w", rawMetricsWriteEndpoint, err)
	}

	cfg.metrics.writeEndpoint = metricsWriteEndpoint

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
