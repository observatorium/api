package authentication

import (
	"context"
	"net/http"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AnonymousAuthenticatorType represents the anonymous authentication provider
// type.
//
// It always authenticates the incoming request and sets the subject's name to
// 'anonymous'. It should only be used for tests and it requires the
// INSECURE_ANONYMOUS_AUTHENTICATOR_ENABLED environment variable to be set to
// 1.
const AnonymousAuthenticatorType = "anonymous"

func init() {
	if v := os.Getenv("INSECURE_ANONYMOUS_AUTHENTICATOR_ENABLED"); v == "1" {
		onboardNewProvider(AnonymousAuthenticatorType, anonymousAuthenticatorType)
	}
}

func anonymousAuthenticatorType(_ map[string]interface{}, _ string, _ *prometheus.CounterVec, logger log.Logger) (Provider, error) {
	level.Warn(logger).Log("msg", "using anonymous authenticator")
	return &anonymousAuthenticator{}, nil
}

type anonymousAuthenticator struct{}

// Middleware implements the Provider interface.
func (a *anonymousAuthenticator) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), subjectKey, "anonymous")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GRPCMiddleware implements the Provider interface.
// It isn't yet implemented.
func (a *anonymousAuthenticator) GRPCMiddleware() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		return ctx, status.Error(codes.Unimplemented, "internal error")
	})
}

// Handler implements the Provider interface.
func (a *anonymousAuthenticator) Handler() (string, http.Handler) {
	return "", nil
}
