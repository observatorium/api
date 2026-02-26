package authentication

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-kit/log"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/observatorium/api/logger"
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

func TestTokenExpiredErrorHandling(t *testing.T) {
	// Test the error handling logic for TokenExpiredError
	t.Run("TokenExpiredError is correctly identified", func(t *testing.T) {
		// Create a TokenExpiredError
		expiredErr := &oidc.TokenExpiredError{
			Expiry: time.Now().Add(-time.Hour), // Expired an hour ago
		}
		
		// Test direct error
		var tokenExpiredErr *oidc.TokenExpiredError
		if !errors.As(expiredErr, &tokenExpiredErr) {
			t.Error("errors.As should identify TokenExpiredError")
		}
		
		// Test wrapped error
		wrappedErr := &wrappedError{
			msg: "verification failed",
			err: expiredErr,
		}
		
		if !errors.As(wrappedErr, &tokenExpiredErr) {
			t.Error("errors.As should identify wrapped TokenExpiredError")
		}
	})
	
	t.Run("Other errors are not identified as TokenExpiredError", func(t *testing.T) {
		// Test with a generic error
		genericErr := errors.New("generic verification error")
		
		var tokenExpiredErr *oidc.TokenExpiredError
		if errors.As(genericErr, &tokenExpiredErr) {
			t.Error("errors.As should not identify generic error as TokenExpiredError")
		}
		
		// Test with wrapped generic error
		wrappedGenericErr := &wrappedError{
			msg: "verification failed",
			err: genericErr,
		}
		
		if errors.As(wrappedGenericErr, &tokenExpiredErr) {
			t.Error("errors.As should not identify wrapped generic error as TokenExpiredError")
		}
	})
}

// Helper type to wrap errors for testing
type wrappedError struct {
	msg string
	err error
}

func (e *wrappedError) Error() string {
	return e.msg
}

func (e *wrappedError) Unwrap() error {
	return e.err
}
