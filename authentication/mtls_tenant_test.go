package authentication

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-kit/log"
)

func TestWithMTLSTenantExtraction(t *testing.T) {
	logger := log.NewNopLogger()
	tenantHeader := "X-Scope-OrgID"

	t.Run("extracts tenant from certificate OU", func(t *testing.T) {
		middleware := WithMTLSTenantExtraction(logger, tenantHeader)

		// Create a mock certificate with OU
		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"team-alpha", "other-ou"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/api/metrics/v1/api/v1/receive", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}

		var capturedTenant string
		var capturedHeader string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := GetTenant(r.Context())
			if ok {
				capturedTenant = tenant
			}
			capturedHeader = r.Header.Get(tenantHeader)
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		if capturedTenant != "team-alpha" {
			t.Errorf("expected tenant 'team-alpha', got '%s'", capturedTenant)
		}

		if capturedHeader != "team-alpha" {
			t.Errorf("expected header 'team-alpha', got '%s'", capturedHeader)
		}
	})

	t.Run("returns 401 when no TLS connection", func(t *testing.T) {
		middleware := WithMTLSTenantExtraction(logger, tenantHeader)

		req := httptest.NewRequest(http.MethodPost, "/api/metrics/v1/api/v1/receive", nil)
		// No req.TLS set

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})

	t.Run("returns 401 when no client certificate", func(t *testing.T) {
		middleware := WithMTLSTenantExtraction(logger, tenantHeader)

		req := httptest.NewRequest(http.MethodPost, "/api/metrics/v1/api/v1/receive", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})

	t.Run("returns 400 when certificate has no OU", func(t *testing.T) {
		middleware := WithMTLSTenantExtraction(logger, tenantHeader)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{}, // Empty OU
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/api/metrics/v1/api/v1/receive", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})

	t.Run("uses first OU when multiple present", func(t *testing.T) {
		middleware := WithMTLSTenantExtraction(logger, tenantHeader)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"first-tenant", "second-tenant"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/api/metrics/v1/api/v1/receive", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}

		var capturedTenant string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, _ := GetTenant(r.Context())
			capturedTenant = tenant
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if capturedTenant != "first-tenant" {
			t.Errorf("expected first OU 'first-tenant', got '%s'", capturedTenant)
		}
	})

	t.Run("forwards tenant header to upstream", func(t *testing.T) {
		middleware := WithMTLSTenantExtraction(logger, tenantHeader)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				OrganizationalUnit: []string{"team-beta"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/api/logs/v1/loki/api/v1/push", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}

		var capturedHeader string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeader = r.Header.Get(tenantHeader)
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if capturedHeader != "team-beta" {
			t.Errorf("expected header 'team-beta', got '%s'", capturedHeader)
		}
	})
}
