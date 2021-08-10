package tenants

import (
	"context"
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
	"path"
	"regexp"
	"time"

	"github.com/ghodss/yaml"
	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/metalmatze/signal/server/signalhttp"
	"github.com/prometheus/client_golang/prometheus"

	logsv1 "github.com/observatorium/api/api/logs/v1"
	metricslegacy "github.com/observatorium/api/api/metrics/legacy"
	metricsv1 "github.com/observatorium/api/api/metrics/v1"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/opa"
	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/ratelimit"
	"github.com/observatorium/api/rbac"
)

const grpcDialTimeout = 1 * time.Second

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

func Register(
	r *chi.Mux,
	tenantsConfPath, rbacConfPath string,
	rateLimiterAddress string,
	metricsConfig MetricsConfig,
	logsConfig LogsConfig,
	logger log.Logger,
	reg *prometheus.Registry,
) {
	// Load all the command line configuration into tenantsConfig struct.
	tCfg := loadTenantConfigs(tenantsConfPath, rbacConfPath, rateLimiterAddress, logger, reg)

	if err := registerTenantRetryMetric(&tCfg); err != nil {
		level.Error(tCfg.logger).Log("msg", "initialize Prometheus registry:", "err", err)
		return
	}

	for _, t := range tCfg.Tenants {
		if t == nil {
			continue
		}

		go newTenant(&metricsConfig, &logsConfig, &tCfg, r, t)
	}
}

// Load RBAC config information from rbac.yaml.
func loadRBACConfig(rbacConfPath string) (rbac.Authorizer, error) {
	f, err := os.Open(rbacConfPath)
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
func loadTenantConfigs(
	tenantsConfPath, rbacConfPath string,
	rateLimiterAddress string,
	logger log.Logger,
	reg *prometheus.Registry,
) tenantsConfig {
	tCfg := tenantsConfig{
		logger: logger,
		reg:    reg,
	}

	f, err := ioutil.ReadFile(tenantsConfPath)
	if err != nil {
		stdlog.Fatalf("cannot read tenant configuration file from path %q: %v", tenantsConfPath, err)
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
	tCfg.authorizer, err = loadRBACConfig(rbacConfPath)
	if err != nil {
		stdlog.Fatalf("unable to read RBAC YAML: %v", err)
		return tCfg
	}

	if rateLimiterAddress != "" {
		ctx, cancel := context.WithTimeout(context.Background(), grpcDialTimeout)
		defer cancel()

		tCfg.rateLimitClient = ratelimit.NewClient(tCfg.reg)
		if err := tCfg.rateLimitClient.Dial(ctx, rateLimiterAddress); err != nil {
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
func newTenant(metricsConfig *MetricsConfig, logsConfig *LogsConfig, tCfg *tenantsConfig, r *chi.Mux, t *tenant) {
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
			r.Use(authentication.WithTenantHeader(metricsConfig.TenantHeader, t.ID))

			if tCfg.rateLimitClient != nil {
				r.Use(ratelimit.WithSharedRateLimiter(tCfg.logger, tCfg.rateLimitClient, rateLimits...))
			} else {
				r.Use(ratelimit.WithLocalRateLimiter(rateLimits...))
			}

			r.Mount("/api/v1/"+t.Name, metricsLegacyHandler(metricsConfig, tCfg, authZ))
			r.Mount("/api/metrics/v1/"+t.Name, stripTenantPrefix(
				"/api/metrics/v1",
				metricsHandler(metricsConfig, tCfg, authZ)),
			)
		})
		// Logs
		if logsConfig.Enabled {
			r.Group(func(r chi.Router) {
				r.Use(authentication.WithTenant(t.Name, t.ID))
				r.Use(authN)
				r.Use(authentication.WithTenantHeader(logsConfig.TenantHeader, t.ID))
				r.Mount("/api/logs/v1/"+t.Name, stripTenantPrefix(
					"/api/logs/v1",
					logsHandler(logsConfig, tCfg, authZ)),
				)
			})
		}

		level.Info(tCfg.logger).Log("msg", "tenant registration is successful", "tenant", t.Name)

		break
	}
}

// metricsLegacyHandler creates handler for legacyMetrics V1 API.
func metricsLegacyHandler(metricsConfig *MetricsConfig, tCfg *tenantsConfig, authZ rbac.Authorizer) http.Handler {
	return metricslegacy.NewHandler(
		metricsConfig.ReadEndpoint,
		metricslegacy.Logger(tCfg.logger),
		metricslegacy.Registry(tCfg.reg),
		metricslegacy.HandlerInstrumenter(tCfg.ins),
		metricslegacy.SpanRoutePrefix("/api/v1/{tenant}"),
		metricslegacy.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")),
		metricslegacy.ReadMiddleware(metricsv1.WithEnforceTenantLabel(metricsConfig.TenantLabel)),
		metricslegacy.UIMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")))
}

// metricsHandler creates handler for Metrics V1 API.
func metricsHandler(metricsConfig *MetricsConfig, tCfg *tenantsConfig, authZ rbac.Authorizer) http.Handler {
	return metricsv1.NewHandler(
		metricsConfig.ReadEndpoint,
		metricsConfig.WriteEndpoint,
		metricsv1.Logger(tCfg.logger),
		metricsv1.Registry(tCfg.reg),
		metricsv1.HandlerInstrumenter(tCfg.ins),
		metricsv1.SpanRoutePrefix("/api/metrics/v1/{tenant}"),
		metricsv1.ReadMiddleware(authorization.WithAuthorizers(authZ, rbac.Read, "metrics")),
		metricsv1.ReadMiddleware(metricsv1.WithEnforceTenantLabel(metricsConfig.TenantLabel)),
		metricsv1.WriteMiddleware(authorization.WithAuthorizers(authZ, rbac.Write, "metrics")),
	)
}

// logsHandler creates handler for Logs V1 API.
func logsHandler(logsConfig *LogsConfig, tCfg *tenantsConfig, authZ rbac.Authorizer) http.Handler {
	return logsv1.NewHandler(
		logsConfig.ReadEndpoint,
		logsConfig.TailEndpoint,
		logsConfig.WriteEndpoint,
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
