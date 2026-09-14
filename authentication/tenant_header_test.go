package authentication

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithTenantFromHeader(t *testing.T) {
	tenantHeader := "X-Scope-OrgID"

	t.Run("extracts tenant from header", func(t *testing.T) {
		middleware := WithTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		req.Header.Set(tenantHeader, "team-alpha")

		var capturedTenant string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := GetTenant(r.Context())
			if ok {
				capturedTenant = tenant
			}
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
	})

	t.Run("returns 400 when header missing", func(t *testing.T) {
		middleware := WithTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		// No header set

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})

	t.Run("returns 400 when header empty", func(t *testing.T) {
		middleware := WithTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		req.Header.Set(tenantHeader, "")

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})

	t.Run("works with different header names", func(t *testing.T) {
		headers := map[string]string{
			"X-Scope-OrgID":  "loki-tenant",
			"THANOS-TENANT":  "thanos-tenant",
			"X-Tenant":       "jaeger-tenant",
			"Custom-Header":  "custom-tenant",
		}

		for headerName, expectedTenant := range headers {
			middleware := WithTenantFromHeader(headerName)

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.Header.Set(headerName, expectedTenant)

			var capturedTenant string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tenant, _ := GetTenant(r.Context())
				capturedTenant = tenant
				w.WriteHeader(http.StatusOK)
			})

			rr := httptest.NewRecorder()
			middleware(handler).ServeHTTP(rr, req)

			if capturedTenant != expectedTenant {
				t.Errorf("header %s: expected tenant '%s', got '%s'", headerName, expectedTenant, capturedTenant)
			}
		}
	})
}

func TestWithOptionalTenantFromHeader(t *testing.T) {
	tenantHeader := "X-Scope-OrgID"

	t.Run("extracts tenant from header when present", func(t *testing.T) {
		middleware := WithOptionalTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		req.Header.Set(tenantHeader, "team-alpha")

		var capturedTenant string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := GetTenant(r.Context())
			if ok {
				capturedTenant = tenant
			}
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
	})

	t.Run("continues without error when header missing", func(t *testing.T) {
		middleware := WithOptionalTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		// No header set

		var handlerCalled bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			_, ok := GetTenant(r.Context())
			if ok {
				t.Error("expected no tenant in context")
			}
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if !handlerCalled {
			t.Error("handler should have been called")
		}

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}
	})

	t.Run("continues without error when header empty", func(t *testing.T) {
		middleware := WithOptionalTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		req.Header.Set(tenantHeader, "")

		var handlerCalled bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			_, ok := GetTenant(r.Context())
			if ok {
				t.Error("expected no tenant in context")
			}
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if !handlerCalled {
			t.Error("handler should have been called")
		}

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}
	})
}
