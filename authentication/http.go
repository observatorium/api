package authentication

import (
	"context"
	"net/http"
	"strings"

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
	// accessTokenKey is the key that holds the bearer token in a request context.
	accessTokenKey contextKey = "accessToken"
	// groupsKey is the key that holds the groups in a request context.
	groupsKey contextKey = "groups"
	// subjectKey is the key that holds the subject in a request context.
	subjectKey contextKey = "subject"
	// tenantKey is the key that holds the tenant in a request context.
	tenantKey contextKey = "tenant"
	// tenantIDKey is the key that holds the tenant ID in a request context.
	tenantIDKey contextKey = "tenantID"
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

// WithTenantID returns a middleware that finds the tenantID using the tenant
// from the URL parameters and adds it to the request context.
func WithTenantID(tenantIDs map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := chi.URLParam(r, "tenant")
			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), tenantIDKey, tenantIDs[tenant]),
			))
		})
	}
}

// WithAccessToken returns a middleware that looks up the authorization access
// token from the request and adds it to the request context.
func WithAccessToken() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken := r.Header.Get("Authorization")
			token := rawToken[strings.LastIndex(rawToken, " ")+1:]
			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), accessTokenKey, token),
			))
		})
	}
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

// GetTenantID extracts the tenant ID from provided context.
func GetTenantID(ctx context.Context) (string, bool) {
	value := ctx.Value(tenantIDKey)
	id, ok := value.(string)

	return id, ok
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

// GetAccessToken extracts the access token from the provided context.
func GetAccessToken(ctx context.Context) (string, bool) {
	value := ctx.Value(accessTokenKey)
	token, ok := value.(string)

	return token, ok
}

// Middleware is a convenience type for functions that wrap http.Handlers.
type Middleware func(http.Handler) http.Handler

// MiddlewareFunc is a function type able to return authentication middleware for
// a given tenant. If no middleware is found, the second return value should be false.
type MiddlewareFunc func(tenant string) (Middleware, bool)

// WithTenantMiddlewares creates a single Middleware for all
// provided tenant-middleware sets.
func WithTenantMiddlewares(mwFns ...MiddlewareFunc) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := GetTenant(r.Context())
			if !ok {
				http.Error(w, "error finding tenant", http.StatusBadRequest)
				return
			}

			for _, mwFn := range mwFns {
				if m, ok := mwFn(tenant); ok {
					m(next).ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "tenant not found, have you registered it?", http.StatusUnauthorized)
		})
	}
}
