package authorization

import (
	"net/http"

	"github.com/observatorium/observatorium/internal/authentication"
	"github.com/observatorium/observatorium/rbac"
)

// WithAuthorizers returns a middleware that authorizes subjects taken from a request context
// for the given permission on the given resource for a tenant taken from a request context.
func WithAuthorizers(authorizers map[string]rbac.Authorizer, permission rbac.Permission, resource string) func(http.Handler) http.Handler {
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
			groups, ok := authentication.GetGroups(r.Context())
			if !ok {
				groups = []string{}
			}
			a, ok := authorizers[tenant]
			if !ok {
				http.Error(w, "error finding tenant", http.StatusUnauthorized)
				return
			}

			if !a.Authorize(subject, groups, permission, resource, tenant) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
