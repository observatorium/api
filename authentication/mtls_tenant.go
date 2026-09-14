package authentication

import (
	"context"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/observatorium/api/httperr"
)

// MTLSTenantExtractor is a middleware that extracts the tenant from the mTLS client certificate's
// OrganizationalUnit (OU) field and sets it in the request context and as a header.
// This is designed for write-path authentication where machines authenticate via mTLS.
type MTLSTenantExtractor struct {
	logger       log.Logger
	tenantHeader string
}

// NewMTLSTenantExtractor creates a new mTLS tenant extractor middleware.
// tenantHeader is the HTTP header name to set the tenant (e.g., "X-Scope-OrgID" for Loki, "THANOS-TENANT" for Thanos).
func NewMTLSTenantExtractor(logger log.Logger, tenantHeader string) *MTLSTenantExtractor {
	return &MTLSTenantExtractor{
		logger:       logger,
		tenantHeader: tenantHeader,
	}
}

// Middleware returns an HTTP middleware that:
// 1. Requires a valid mTLS client certificate
// 2. Extracts the tenant from the certificate's OU field
// 3. Sets the tenant in request context and as a header for upstream forwarding
func (e *MTLSTenantExtractor) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				level.Debug(e.logger).Log("msg", "no TLS connection")
				httperr.PrometheusAPIError(w, "TLS connection required", http.StatusUnauthorized)
				return
			}

			if len(r.TLS.PeerCertificates) == 0 {
				level.Debug(e.logger).Log("msg", "no client certificate presented")
				httperr.PrometheusAPIError(w, "client certificate required", http.StatusUnauthorized)
				return
			}

			cert := r.TLS.PeerCertificates[0]

			// Note: Certificate has already been verified by the TLS handshake when
			// the server is configured with RequireAndVerifyClientCert.
			// We just need to extract the tenant from the OU field.

			// Extract tenant from OrganizationalUnit field
			if len(cert.Subject.OrganizationalUnit) == 0 {
				level.Debug(e.logger).Log("msg", "no organizational unit in client certificate")
				httperr.PrometheusAPIError(w, "tenant not found in certificate OU", http.StatusBadRequest)
				return
			}

			// Use the first OU as the tenant identifier
			tenant := cert.Subject.OrganizationalUnit[0]

			level.Debug(e.logger).Log("msg", "extracted tenant from mTLS certificate", "tenant", tenant)

			// Set tenant in request context
			ctx := context.WithValue(r.Context(), tenantKey, tenant)

			// Set tenant header for upstream forwarding
			r.Header.Set(e.tenantHeader, tenant)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithMTLSTenantExtraction returns a middleware function that extracts tenant from mTLS certificates.
// This is a convenience function for use in the main.go middleware chains.
func WithMTLSTenantExtraction(logger log.Logger, tenantHeader string) Middleware {
	extractor := NewMTLSTenantExtractor(logger, tenantHeader)
	return extractor.Middleware()
}
