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

// WithTenant finds the tenant from the URL parameters and adds it to the request context.
func WithTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.URL.Query().Get(tenantKey.String())
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), tenantKey, tenant),
		))
	})
}

// WithTenantID returns a middleware that finds the tenantID using the tenant
// from the URL parameters and adds it to the request context.
func WithTenantID(tenantName, tenantID string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			queryValues := r.URL.Query()
			queryValues.Add(tenantKey.String(), tenantName)
			r.URL.RawQuery = queryValues.Encode()

			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), tenantIDKey, tenantID),
			))
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
