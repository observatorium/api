package authentication

import (
	"context"
	"net/http"

	"github.com/observatorium/api/httperr"
)

// WithTenantFromHeader extracts the tenant from the specified HTTP header and adds it to the request context.
// This is designed for read-path authentication where clients (like Grafana) specify the tenant via headers.
//
// For example:
//   - Loki uses "X-Scope-OrgID"
//   - Thanos/Prometheus uses "THANOS-TENANT"
//   - Jaeger uses "X-Tenant"
func WithTenantFromHeader(tenantHeader string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := r.Header.Get(tenantHeader)
			if tenant == "" {
				httperr.PrometheusAPIError(w, "tenant header required", http.StatusBadRequest)
				return
			}

			// Set tenant in request context for downstream middleware
			ctx := context.WithValue(r.Context(), tenantKey, tenant)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithOptionalTenantFromHeader extracts the tenant from the header if present, otherwise continues without error.
// This is useful for endpoints that can work with or without a tenant specified.
func WithOptionalTenantFromHeader(tenantHeader string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := r.Header.Get(tenantHeader)
			if tenant != "" {
				ctx := context.WithValue(r.Context(), tenantKey, tenant)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
