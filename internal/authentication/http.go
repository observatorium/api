package authentication

import (
	"context"
	"net/http"

	"github.com/go-chi/chi"
)

// contextKey to use when setting context values in the HTTP package.
type contextKey string

// String implements the Stringer interface and makes it
// nice to print contexts.
func (c contextKey) String() string {
	return "HTTP context key " + string(c)
}

const (
	// groupsKey is the key that holds the groups in a request context.
	groupsKey contextKey = "groups"
	// subjectKey is the key that holds the subject in a request context.
	subjectKey contextKey = "subject"
	// tenantKey is the key that holds the tenant in a request context.
	tenantKey contextKey = "tenant"
)

// WithTenant finds the tenant from the URL parameters and adds it to the request context.
func WithTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := chi.URLParam(r, "tenant")
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), tenantKey, tenant),
		))
	})
}

// WithTenantHeader returns a new middleware that adds the ID of the tenant to the specified header.
func WithTenantHeader(header string, tenantIDs map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := chi.URLParam(r, "tenant")
			r.Header.Add(header, tenantIDs[tenant])
			next.ServeHTTP(w, r)
		})
	}
}

// GetTenant extracts the tenant from provided context.
func GetTenant(ctx context.Context) (string, bool) {
	value := ctx.Value(tenantKey)
	tenant, ok := value.(string)

	return tenant, ok
}

// GetSubject extracts the subject from provided context.
func GetSubject(ctx context.Context) (string, bool) {
	value := ctx.Value(subjectKey)
	subject, ok := value.(string)

	return subject, ok
}

// GetGroups extracts the groups from provided context.
func GetGroups(ctx context.Context) ([]string, bool) {
	value := ctx.Value(groupsKey)
	groups, ok := value.([]string)

	return groups, ok
}

// WithTenantMiddlewares creates a single Middleware for all
// provided tenant-middleware sets.
func WithTenantMiddlewares(middlewareSets ...map[string]Middleware) Middleware {
	middlewares := map[string]Middleware{}
	for _, ms := range middlewareSets {
		for t, m := range ms {
			middlewares[t] = m
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := GetTenant(r.Context())
			if !ok {
				http.Error(w, "error finding tenant", http.StatusBadRequest)
				return
			}
			m, ok := middlewares[tenant]
			if !ok {
				http.Error(w, "error finding tenant", http.StatusUnauthorized)
				return
			}

			m(next).ServeHTTP(w, r)
		})
	}
}
