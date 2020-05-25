package authorization

import (
	"net/http"

	"github.com/observatorium/observatorium/internal/authentication"
	"github.com/observatorium/observatorium/rbac"
)

// WithAuthorizer returns a middleware that authorizes subjects taken from a request context
// for the given permission on the given resource for a tenant taken from a request context.
func WithAuthorizer(a rbac.Authorizer, permission rbac.Permission, resource string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				http.Error(w, "error finding tenant", http.StatusInternalServerError)
				return
			}
			subject, ok := authentication.GetSubject(r.Context())
			if !ok {
				http.Error(w, "unknown subject", http.StatusUnauthorized)
				return
			}
			if !a.Authorize(subject, permission, resource, tenant) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
