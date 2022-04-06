package authentication

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

//nolint:gochecknoglobals
// providerFactories map is used for the providers' self-registration.
var providerFactories map[string]ProviderFactory

//nolint:gochecknoglobals
// providersMtx is used to protect the providerFactories.
var providersMtx sync.RWMutex

//nolint:gochecknoinits
func init() {
	providerFactories = make(map[string]ProviderFactory)
}

// onboardNewProvider is used by the providers to register themselves.
func onboardNewProvider(providerType string, factory ProviderFactory) {
	providersMtx.Lock()
	defer providersMtx.Unlock()

	providerFactories[providerType] = factory
}

// ProviderFactory represents each authenticator factory, a function to create a new corresponding
// authentication provider.
type ProviderFactory func(config map[string]interface{}, tenant string, registrationRetryCount *prometheus.CounterVec, logger log.Logger) (Provider, error)

// Provider is an interface that should be implemented to onboard a new authentication
// provider.
type Provider interface {
	Middleware() Middleware
	GRPCMiddleware() grpc.StreamServerInterceptor
	Handler() (string, http.Handler)
	LoginPath(tenant string) string
}

type tenantHandlers map[string]http.Handler

// ProviderManager manages all middleware and handlers of all authenticators.
type ProviderManager struct {
	mtx                    sync.RWMutex
	patternHandlers        map[string]tenantHandlers
	middlewares            map[string]Middleware
	gRPCInterceptors       map[string]grpc.StreamServerInterceptor
	authenticator          map[string]Provider
	logger                 log.Logger
	registrationRetryCount *prometheus.CounterVec
}

// NewProviderManager creates a new authentication handler.
func NewProviderManager(l log.Logger, registrationRetryCount *prometheus.CounterVec) *ProviderManager {
	return &ProviderManager{
		registrationRetryCount: registrationRetryCount,
		patternHandlers:        make(map[string]tenantHandlers),
		middlewares:            make(map[string]Middleware),
		gRPCInterceptors:       make(map[string]grpc.StreamServerInterceptor),
		authenticator:          make(map[string]Provider),
		logger:                 l,
	}
}

// InitializeProvider initializes an authenticator provider and register the created
// authentication middleware and handler.
func (ah *ProviderManager) InitializeProvider(config map[string]interface{},
	tenant string, authenticatorType string, registrationRetryCount *prometheus.CounterVec, logger log.Logger) chan Provider {
	authCh := make(chan Provider)

	go func() {
		ProviderFactory, err := getProviderFactory(authenticatorType)
		if err != nil {
			level.Error(ah.logger).Log("msg", err, "tenant", tenant, "authenticator", authenticatorType)
			authCh <- nil
			return
		}

		authenticator, err := ProviderFactory(config, tenant, registrationRetryCount, logger)
		if err != nil {
			level.Error(ah.logger).Log("msg", err, "tenant", tenant, "authenticator", authenticatorType)
			authCh <- nil
			return
		}

		ah.mtx.Lock()
		ah.middlewares[tenant] = authenticator.Middleware()
		ah.gRPCInterceptors[tenant] = authenticator.GRPCMiddleware()
		ah.authenticator[tenant] = authenticator
		pattern, handler := authenticator.Handler()
		if pattern != "" && handler != nil {
			if ah.patternHandlers[pattern] == nil {
				ah.patternHandlers[pattern] = make(tenantHandlers)
			}
			ah.patternHandlers[pattern][tenant] = handler
		}
		ah.mtx.Unlock()

		level.Debug(ah.logger).Log("msg", "successfully initialized authenticator", "tenant", tenant, "authenticator", authenticatorType)
		authCh <- authenticator
	}()

	return authCh
}

// Middleware returns an authentication middleware for a tenant.
func (ah *ProviderManager) Middlewares(tenant string) (Middleware, bool) {
	ah.mtx.RLock()
	mw, ok := ah.middlewares[tenant]
	ah.mtx.RUnlock()

	return mw, ok
}

// GRPCMiddlewares returns an authentication interceptor for a tenant.
func (ah *ProviderManager) GRPCMiddlewares(tenant string) (grpc.StreamServerInterceptor, bool) {
	ah.mtx.RLock()
	mw, ok := ah.gRPCInterceptors[tenant]
	ah.mtx.RUnlock()

	return mw, ok
}

// PatternHandler return an http.HandlerFunc for a corresponding pattern.
func (ah *ProviderManager) PatternHandler(pattern string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := GetTenant(r.Context())
		const msg = "error finding tenant"
		if !ok {
			level.Warn(ah.logger).Log("msg", msg, "tenant", tenant)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		ah.mtx.RLock()
		h, ok := ah.patternHandlers[pattern][tenant]
		ah.mtx.RUnlock()
		if !ok {
			level.Debug(ah.logger).Log("msg", msg, "tenant", tenant)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (ah *ProviderManager) GetLoginPath(tenant string) (string, bool) {
	ah.mtx.RLock()
	provider, ok := ah.authenticator[tenant]
	ah.mtx.RUnlock()

	if !ok {
		return "", false
	}

	return provider.LoginPath(tenant), true
}

func getProviderFactory(authType string) (ProviderFactory, error) {
	providersMtx.RLock()
	defer providersMtx.RUnlock()

	ProviderFactory, ok := providerFactories[authType]
	if !ok {
		return nil, fmt.Errorf("authenticator type %s is not supported", authType)
	}

	return ProviderFactory, nil
}
