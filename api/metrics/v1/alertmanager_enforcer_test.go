package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/alertmanager/api/v2/models"

	"github.com/observatorium/api/authentication"
)

func TestHasMatcherForLabel(t *testing.T) {
	t.Parallel()

	label := "tenant_id"
	tenantA := "1610b0c3-c509-4592-a256-a1871353dbfa"
	falsy := false
	truthy := true

	matchersFor := func(tenantID string) models.Matchers {
		return models.Matchers{
			{
				Name:    strPtr(label),
				Value:   strPtr(tenantID),
				IsRegex: &falsy,
			},
			{
				Name:    strPtr("severity"),
				Value:   strPtr("critical"),
				IsRegex: &falsy,
			},
		}
	}

	tests := []struct {
		name     string
		matchers models.Matchers
		want     bool
	}{
		{
			name:     "tenant matcher present",
			matchers: matchersFor(tenantA),
			want:     true,
		},
		{
			name:     "different tenant",
			matchers: matchersFor("tenant-b"),
			want:     false,
		},
		{
			name: "regex tenant matcher",
			matchers: models.Matchers{
				{
					Name:    strPtr(label),
					Value:   strPtr(tenantA),
					IsRegex: &truthy,
				},
			},
			want: false,
		},
		{
			name:     "no tenant matcher",
			matchers: matchersFor(tenantA)[1:],
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hasMatcherForLabel(tc.matchers, label, tenantA); got != tc.want {
				t.Fatalf("hasMatcherForLabel() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWithEnforceTenancyOnSilenceID(t *testing.T) {
	t.Parallel()

	const (
		label      = "tenant_id"
		tenantName = "test-oidc"
		tenantID   = "1610b0c3-c509-4592-a256-a1871353dbfa"
		silID      = "802146e0-1f7a-42a6-ab0e-1e631479970b"
	)

	silenceJSON := func(tenant string) string {
		t.Helper()
		return `{
  "id": "` + silID + `",
  "status": {
    "state": "active"
  },
  "updatedAt": "2020-01-15T09:06:23.419Z",
  "comment": "comment",
  "createdBy": "author",
  "endsAt": "2020-02-13T13:00:02.084Z",
  "matchers": [
    {
      "isRegex": false,
      "name": "` + label + `",
      "value": "` + tenant + `"
    }
  ],
  "startsAt": "2020-02-13T12:02:01.000Z"
}`
	}

	newRouter := func(t *testing.T, upstream http.Handler, next http.Handler) *chi.Mux {
		t.Helper()

		srv := httptest.NewServer(upstream)
		t.Cleanup(srv.Close)

		upstreamURL, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}

		r := chi.NewRouter()
		r.Use(authentication.WithTenant)
		r.Use(authentication.WithTenantID(map[string]string{tenantName: tenantID}))
		r.With(WithEnforceTenancyOnSilenceID(label, upstreamURL, srv.Client().Transport)).Method(
			http.MethodGet,
			"/{tenant}/am/api/v2/silence/{silenceID}",
			next,
		)
		r.With(WithEnforceTenancyOnSilenceID(label, upstreamURL, srv.Client().Transport)).Method(
			http.MethodDelete,
			"/{tenant}/am/api/v2/silence/{silenceID}",
			next,
		)

		return r
	}

	newRequest := func(method string) *http.Request {
		req := httptest.NewRequest(method, "/"+tenantName+"/am/api/v2/silence/"+silID, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("tenant", tenantName)
		rctx.URLParams.Add("silenceID", silID)
		return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}

	t.Run("proxies get when silence belongs to tenant", func(t *testing.T) {
		t.Parallel()

		var proxyCalled bool
		upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v2/silence/"+silID {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(silenceJSON(tenantID)))
				return
			}
			http.NotFound(w, r)
		})
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			proxyCalled = true
			w.WriteHeader(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		newRouter(t, upstream, next).ServeHTTP(rec, newRequest(http.MethodGet))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
		if !proxyCalled {
			t.Fatal("expected request to be proxied")
		}
	})

	t.Run("proxies delete when silence belongs to tenant", func(t *testing.T) {
		t.Parallel()

		var deleteCalled bool
		upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v2/silence/"+silID:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(silenceJSON(tenantID)))
			case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/silence/"+silID:
				deleteCalled = true
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		})
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		newRouter(t, upstream, next).ServeHTTP(rec, newRequest(http.MethodDelete))

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
		if !deleteCalled {
			t.Fatal("expected delete to be proxied")
		}
	})

	t.Run("forbidden when silence belongs to another tenant", func(t *testing.T) {
		t.Parallel()

		upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/v2/silence/"+silID {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(silenceJSON("other-tenant")))
				return
			}
			http.NotFound(w, r)
		})

		rec := httptest.NewRecorder()
		newRouter(t, upstream, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("request should not be proxied")
		})).ServeHTTP(rec, newRequest(http.MethodGet))

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
		}
	})

	t.Run("not found when silence is missing", func(t *testing.T) {
		t.Parallel()

		upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		rec := httptest.NewRecorder()
		newRouter(t, upstream, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("request should not be proxied")
		})).ServeHTTP(rec, newRequest(http.MethodDelete))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
		}
	})
}

func strPtr(s string) *string {
	return &s
}
