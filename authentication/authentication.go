package authentication

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

//nolint:gochecknoglobals
// authenticatorFactories map is used for the providers' self-registration.
var authenticatorFactories map[string]AuthenticatorFactory

//nolint:gochecknoglobals
// authenticatorsMtx is used to protect the authenticatorFactories.
var authenticatorsMtx sync.RWMutex

//nolint:gochecknoinits
func init() {
	authenticatorFactories = make(map[string]AuthenticatorFactory)
}

// onboardNewProvider is used by the providers to register themselves.
func onboardNewProvider(providerType string, factory AuthenticatorFactory) {
	authenticatorsMtx.Lock()
	defer authenticatorsMtx.Unlock()

	authenticatorFactories[providerType] = factory
}

// AuthenticatorFactory represents each authenticator factory, a function to create a new corresponding
// authentication provider.
type AuthenticatorFactory func(config map[string]interface{}, tenant string, registrationRetryCount *prometheus.CounterVec, logger log.Logger) (Provider, error)

// Provider is an interface that should be implemented to onboard a new authentication.
// provider.
type Provider interface {
	Middleware() Middleware
	Handler() (string, http.Handler)
}

type tenantHandlers map[string]http.Handler

// AuthenticatorsHandlers manages all middleware and handlers of all authenticators.
type AuthenticatorsHandlers struct {
	mtx                    sync.RWMutex
	patternHandlers        map[string]tenantHandlers
	middlewares            map[string]Middleware
	logger                 log.Logger
	registrationRetryCount *prometheus.CounterVec
}

// NewAuthenticatorsHandlers creates a new authentication handler.
func NewAuthenticatorsHandlers(l log.Logger, registrationRetryCount *prometheus.CounterVec) *AuthenticatorsHandlers {
	return &AuthenticatorsHandlers{
		registrationRetryCount: registrationRetryCount,
		patternHandlers:        make(map[string]tenantHandlers),
		middlewares:            make(map[string]Middleware),
		logger:                 l,
	}
}

// NewTenantAuthenticator initializes an authenticator provider and register the created
// authentication middleware and handler.
func (ah *AuthenticatorsHandlers) NewTenantAuthenticator(config map[string]interface{},
	tenant string, authenticatorType string, registrationRetryCount *prometheus.CounterVec, logger log.Logger) chan Provider {
	authCh := make(chan Provider)

	go func() {
		authenticatorFactory, err := getAuthenticatorFactory(authenticatorType)
		if err != nil {
			level.Error(ah.logger).Log("msg", err, "tenant", tenant, "authenticator", authenticatorType)
			authCh <- nil
			return
		}

		authenticator, err := authenticatorFactory(config, tenant, registrationRetryCount, logger)
		if err != nil {
			level.Error(ah.logger).Log("msg", err, "tenant", tenant, "authenticator", authenticatorType)
			authCh <- nil
			return
		}

		ah.mtx.Lock()
		ah.middlewares[tenant] = authenticator.Middleware()
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

func (ah *AuthenticatorsHandlers) AuthenticatorMiddlewares(tenant string) (Middleware, bool) {
	ah.mtx.RLock()
	mw, ok := ah.middlewares[tenant]
	ah.mtx.RUnlock()

	return mw, ok
}

func (ah *AuthenticatorsHandlers) PatternRoutes(pattern string) http.HandlerFunc {
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

func getAuthenticatorFactory(authType string) (AuthenticatorFactory, error) {
	authenticatorsMtx.RLock()
	defer authenticatorsMtx.RUnlock()

	authenticatorFactory, ok := authenticatorFactories[authType]
	if !ok {
		return nil, fmt.Errorf("authenticator type %s is not supported", authType)
	}

	return authenticatorFactory, nil
}
