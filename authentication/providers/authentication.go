package providers

import (
	"fmt"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"net/http"

	"github.com/observatorium/api/authentication"
)

//nolint:gochecknoglobals
// authenticatorsFactories map is used by the authentication providers
// to self-register themselves.
var authenticatorsFactories map[string]AuthenticatorFactory

//nolint:gochecknoglobals
// registrationRetryCount used by authenticator providers to count
// registration failures per tenant.
var registrationRetryCount *prometheus.CounterVec

//nolint:gochecknoinits
func init() {
	authenticatorsFactories = make(map[string]AuthenticatorFactory)
}

// AuthenticatorFactory represents each authenticator factor, a function to create a new corresponding
// authentication provider.
type AuthenticatorFactory func(c map[string]interface{}, tenant string, logger log.Logger) (AuthenticationProvider, error)

// AuthenticationProvider interface should be implemented to onboard a new authentication
// provider.
type AuthenticationProvider interface {
	AuthenticationMiddleware(next http.Handler) http.Handler
	GetHandler() (string, http.Handler)
	GetTenant() string
}

type tenantsHandlers map[string]http.Handler

// AuthenticatorsHandlers manages all middleware and handlers of all authenticators
type AuthenticatorsHandlers struct {
	mtx              sync.RWMutex
	patternsHandlers map[string]tenantsHandlers
	middlewares      map[string]authentication.Middleware
	logger           log.Logger
}

// NewAuthenticatorsHandlers create a new authentication handler
func NewAuthenticatorsHandlers(l log.Logger, reg prometheus.Registerer) *AuthenticatorsHandlers {
	registrationRetryCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "observatorium",
		Subsystem: "api",
		Name:      "tenants_authenticator_failed_registrations",
		Help:      "The number of failed authentication provider instantiations.",
	}, []string{"tenant", "authenticator"})

	reg.MustRegister(registrationRetryCount)

	return &AuthenticatorsHandlers{
		patternsHandlers: make(map[string]tenantsHandlers),
		middlewares:      make(map[string]authentication.Middleware),
		logger:           l,
	}
}

// NewTenantAuthenticator initializes an authenticator provider and register the created
// authentication middleware and handlers.
func (ah *AuthenticatorsHandlers) NewTenantAuthenticator(config map[string]interface{},
	tenant string, authenticatorType string, logger log.Logger) chan AuthenticationProvider {
	authCh := make(chan AuthenticationProvider)

	go func() {
		authenticatorFactory, err := ah.getAuthenticatorFactory(authenticatorType)
		if err != nil {
			level.Error(ah.logger).Log("msg", err, "tenant", tenant)
			authCh <- nil
			return
		}

		authenticator, err := authenticatorFactory(config, tenant, logger)
		if err != nil {
			level.Error(ah.logger).Log("msg", err, "tenant", tenant)
			authCh <- nil
			return
		}

		ah.mtx.Lock()
		ah.middlewares[authenticator.GetTenant()] = ah.getAuthenticatorMiddleware(authenticator)
		pattern, handler := authenticator.GetHandler()
		if pattern != "" && handler != nil {
			if ah.patternsHandlers[pattern] == nil {
				ah.patternsHandlers[pattern] = make(tenantsHandlers)
			}
			ah.patternsHandlers[pattern][authenticator.GetTenant()] = handler
		}
		ah.mtx.Unlock()

		level.Debug(ah.logger).Log("msg", fmt.Sprintf("successfully initialized authenticator %s", authenticatorType), "tenant", tenant)
		authCh <- authenticator
	}()

	return authCh
}

func (ah *AuthenticatorsHandlers) AuthenticatorMiddlewares(tenant string) (authentication.Middleware, bool) {
	ah.mtx.RLock()
	mw, ok := ah.middlewares[tenant]
	ah.mtx.RUnlock()

	return mw, ok
}

func (ah *AuthenticatorsHandlers) Routes() map[string]http.HandlerFunc {
	handlers := make(map[string]http.HandlerFunc)
	patternHandler := func(pattern string) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			const msg = "error finding tenant"
			if !ok {
				level.Warn(ah.logger).Log("msg", msg, "tenant", tenant)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}

			h, ok := ah.patternsHandlers[pattern][tenant]
			if !ok {
				level.Debug(ah.logger).Log("msg", msg, "tenant", tenant)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, r)
		})
	}

	for pattern := range ah.patternsHandlers {
		handlers[pattern] = patternHandler(pattern)
	}

	return handlers
}

func (ah *AuthenticatorsHandlers) getAuthenticatorFactory(authType string) (AuthenticatorFactory, error) {
	authenticatorFactory, ok := authenticatorsFactories[authType]
	if !ok {
		return nil, fmt.Errorf("authenticator of type: %s is not supported", authType)
	}

	return authenticatorFactory, nil
}

func (ah *AuthenticatorsHandlers) getAuthenticatorMiddleware(authenticator AuthenticationProvider) authentication.Middleware {
	return func(next http.Handler) http.Handler {
		authMiddleware := authenticator.AuthenticationMiddleware(next)
		return authMiddleware
	}
}
