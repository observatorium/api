package providers

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/logger"
	"github.com/prometheus/client_golang/prometheus"
)

type DummyAuthenticator struct {
	tenant string
	logger log.Logger
	Config DummyAuthenticatorConfig
}

type DummyAuthenticatorConfig struct {
	Name string `json:"name"`
}

func (a DummyAuthenticator) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type key string
		const authenticatedKey key = "authenticated"
		ctx := context.WithValue(r.Context(), authenticatedKey, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a DummyAuthenticator) GetHandler() http.Handler {
	return nil
}

func (a DummyAuthenticator) GetTenant() string {
	return a.tenant
}

func newDummyAuthenticator(c map[string]interface{}, tenant string, logger log.Logger) (AuthenticationProvider, error) {
	var config DummyAuthenticatorConfig
	err := mapstructure.Decode(c, &config)

	if err != nil {
		return nil, err
	}

	return &DummyAuthenticator{
		tenant: tenant,
		logger: logger,
		Config: config,
	}, nil
}

func TestNewAuthentication(t *testing.T) {
	authenticatorTypeName := "dummyAuthenticator"
	dummyConfig := map[string]interface{}{"name": "test"}
	l := logger.NewLogger("info", logger.LogFormatLogfmt, "")

	// Register the authenticator factory
	authenticatorsFactories[authenticatorTypeName] = newDummyAuthenticator

	tenant := "test-tenant"

	reg := prometheus.NewRegistry()
	ah := NewAuthenticatorsHandlers(l, reg)

	t.Run("Getting an authenticator factory", func(t *testing.T) {
		_, err := ah.getAuthenticatorFactory(authenticatorTypeName)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		_, err = ah.getAuthenticatorFactory("unregistered-authenticator")
		if err == nil {
			t.Fatalf("getting an authenticator factory of unregistered authenticator should fail")
		}
	})

	t.Run("initialize authenticators", func(t *testing.T) {
		initializedAuthenticator := <-ah.NewTenantAuthenticator(dummyConfig, tenant, authenticatorTypeName, l)
		if initializedAuthenticator == nil {
			t.Fatalf("initialized authenticator should not be nil")
		}

		_, ok := ah.AuthenticatorMiddlewares(tenant)
		if !ok {
			t.Fatalf("middleware of the dummy authenticator has not been found")
		}

		handler := initializedAuthenticator.GetHandler()
		if handler != nil {
			t.Fatalf("getting undefined handler should be nil")
		}

		nonExistAuthenticator := <-ah.NewTenantAuthenticator(dummyConfig, tenant, "not-exist", l)
		if nonExistAuthenticator != nil {
			t.Fatalf("intializing a non-exist authenticator should return a nil authenticator")
		}
	})
}
