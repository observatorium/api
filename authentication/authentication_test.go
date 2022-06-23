package authentication

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-kit/log"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/logger"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

type dummyAuthenticator struct {
	tenant string
	logger log.Logger
	Config dummyAuthenticatorConfig
}

type dummyAuthenticatorConfig struct {
	Name string `json:"name"`
}

func (a dummyAuthenticator) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type key string
			const authenticatedKey key = "authenticated"
			ctx := context.WithValue(r.Context(), authenticatedKey, true)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (a dummyAuthenticator) GRPCMiddleware() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		type key string
		const authenticatedKey key = "authenticated"
		return context.WithValue(ctx, authenticatedKey, true), nil
	})
}

func (a dummyAuthenticator) Handler() (string, http.Handler) {
	return "", nil
}

func newdummyAuthenticator(c map[string]interface{}, tenant string, registrationRetryCount *prometheus.CounterVec, logger log.Logger) (Provider, error) {
	var config dummyAuthenticatorConfig

	err := mapstructure.Decode(c, &config)
	if err != nil {
		return nil, err
	}

	return &dummyAuthenticator{
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
	providerFactories[authenticatorTypeName] = newdummyAuthenticator

	tenant := "test-tenant"

	reg := prometheus.NewRegistry()
	registrationFailingMetric := RegisterTenantsFailingMetric(reg)
	pm := NewProviderManager(l, registrationFailingMetric)

	t.Run("Getting an authenticator factory", func(t *testing.T) {
		_, err := getProviderFactory(authenticatorTypeName)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		_, err = getProviderFactory("unregistered-authenticator")
		if err == nil {
			t.Fatalf("getting an authenticator factory of unregistered authenticator should fail")
		}
	})

	t.Run("initialize authenticators", func(t *testing.T) {
		initializedProvider := <-pm.InitializeProvider(dummyConfig, tenant, authenticatorTypeName, registrationFailingMetric, l)
		if initializedProvider == nil {
			t.Fatalf("initialized authenticator should not be nil")
		}

		_, ok := pm.Middlewares(tenant)
		if !ok {
			t.Fatalf("middleware of the dummy authenticator has not been found")
		}

		_, handler := initializedProvider.Handler()
		if handler != nil {
			t.Fatalf("getting undefined handler should be nil")
		}

		nonExistantProvider := <-pm.InitializeProvider(dummyConfig, tenant, "not-exist", registrationFailingMetric, l)
		if nonExistantProvider != nil {
			t.Fatalf("intializing a non-exist authenticator should return a nil authenticator")
		}
	})
}
