package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/observatorium/api/authentication"
)

// mockTenantHandler wraps a test handler with tenant context setup
func mockTenantHandler(t *testing.T, tenant string, testHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set tenant as URL param (what authentication.WithTenant expects)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("tenant", tenant)
		ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
		r = r.WithContext(ctx)

		// Use authentication.WithTenant to properly set tenant in context
		authentication.WithTenant(testHandler).ServeHTTP(w, r)
	})
}

func TestWithTenantLabel(t *testing.T) {
	tenantLabelName := "tenant_id"

	t.Run("single tenant creates exact match", func(t *testing.T) {
		var capturedData string
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := GetData(r.Context())
			if ok {
				capturedData = data
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := WithTenantLabel(tenantLabelName)
		handler := mockTenantHandler(t, "team-alpha", middleware(innerHandler))

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/query", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		// Verify matchers were created correctly
		var matchers []*labels.Matcher
		if err := json.Unmarshal([]byte(capturedData), &matchers); err != nil {
			t.Fatalf("failed to unmarshal matchers: %v", err)
		}

		if len(matchers) != 1 {
			t.Fatalf("expected 1 matcher, got %d", len(matchers))
		}

		m := matchers[0]
		if m.Type != labels.MatchEqual {
			t.Errorf("expected MatchEqual, got %v", m.Type)
		}
		if m.Name != tenantLabelName {
			t.Errorf("expected name %s, got %s", tenantLabelName, m.Name)
		}
		if m.Value != "team-alpha" {
			t.Errorf("expected value 'team-alpha', got %s", m.Value)
		}
	})

	t.Run("multiple tenants creates regex match", func(t *testing.T) {
		var capturedData string
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := GetData(r.Context())
			if ok {
				capturedData = data
			}
			w.WriteHeader(http.StatusOK)
		})

		middleware := WithTenantLabel(tenantLabelName)
		handler := mockTenantHandler(t, "team-alpha|team-beta|team-gamma", middleware(innerHandler))

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/query", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		// Verify matchers were created correctly
		var matchers []*labels.Matcher
		if err := json.Unmarshal([]byte(capturedData), &matchers); err != nil {
			t.Fatalf("failed to unmarshal matchers: %v", err)
		}

		if len(matchers) != 1 {
			t.Fatalf("expected 1 matcher, got %d", len(matchers))
		}

		m := matchers[0]
		if m.Type != labels.MatchRegexp {
			t.Errorf("expected MatchRegexp, got %v", m.Type)
		}
		if m.Name != tenantLabelName {
			t.Errorf("expected name %s, got %s", tenantLabelName, m.Name)
		}
		if m.Value != "team-alpha|team-beta|team-gamma" {
			t.Errorf("expected value 'team-alpha|team-beta|team-gamma', got %s", m.Value)
		}
	})

	t.Run("returns 400 when no tenant in context", func(t *testing.T) {
		middleware := WithTenantLabel(tenantLabelName)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		})

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/query", nil)
		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})

	t.Run("handles two tenants", func(t *testing.T) {
		var capturedData string
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := GetData(r.Context())
			capturedData = data
			w.WriteHeader(http.StatusOK)
		})

		middleware := WithTenantLabel(tenantLabelName)
		handler := mockTenantHandler(t, "tenant-a|tenant-b", middleware(innerHandler))

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/query", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		var matchers []*labels.Matcher
		json.Unmarshal([]byte(capturedData), &matchers)

		if len(matchers) == 0 {
			t.Fatal("expected matchers to be set")
		}

		if matchers[0].Type != labels.MatchRegexp {
			t.Errorf("expected MatchRegexp for 2 tenants, got %v", matchers[0].Type)
		}
		if matchers[0].Value != "tenant-a|tenant-b" {
			t.Errorf("expected 'tenant-a|tenant-b', got %s", matchers[0].Value)
		}
	})

	t.Run("works with different label names", func(t *testing.T) {
		customLabelName := "custom_tenant_label"
		var capturedData string
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := GetData(r.Context())
			capturedData = data
			w.WriteHeader(http.StatusOK)
		})

		middleware := WithTenantLabel(customLabelName)
		handler := mockTenantHandler(t, "my-tenant", middleware(innerHandler))

		req := httptest.NewRequest(http.MethodGet, "/api/metrics/v1/query", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		var matchers []*labels.Matcher
		json.Unmarshal([]byte(capturedData), &matchers)

		if len(matchers) == 0 {
			t.Fatal("expected matchers to be set")
		}

		if matchers[0].Name != customLabelName {
			t.Errorf("expected label name %s, got %s", customLabelName, matchers[0].Name)
		}
	})
}

func TestGetData(t *testing.T) {
	t.Run("returns data when present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := WithData(req.Context(), "test-data")
		data, ok := GetData(ctx)

		if !ok {
			t.Error("expected ok to be true")
		}
		if data != "test-data" {
			t.Errorf("expected 'test-data', got %s", data)
		}
	})

	t.Run("returns false when not present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		data, ok := GetData(req.Context())

		if ok {
			t.Error("expected ok to be false")
		}
		if data != "" {
			t.Errorf("expected empty string, got %s", data)
		}
	})
}
