package authentication

import (
	"context"
	"net/http"
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
	// tenantIDKey is the key that holds the tenant ID in a request context.
	tenantIDKey contextKey = "tenantID"
)

// WithTenant returns a middleware with request context
// containing both ID and name of a tenant.
func WithTenant(tenantName, tenantID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add tenant ID to the request context.
			ctx := context.WithValue(r.Context(), tenantIDKey, tenantID)
			// Add tenant name to the request context.
			ctx = context.WithValue(ctx, tenantKey, tenantName)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithTenantHeader returns a new middleware that adds the ID of the tenant to the specified header.
func WithTenantHeader(header string, tenantID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Add(header, tenantID)
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

// Creates a single Middleware.
func WithTenantMiddleware(middleware Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok := GetTenant(r.Context())
			if !ok {
				http.Error(w, "error finding tenant", http.StatusBadRequest)
				return
			}
			if middleware == nil {
				http.Error(w, "error finding tenant", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
