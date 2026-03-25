package authentication

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/efficientgo/core/backoff"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/observatorium/api/authentication/openshift"
	"github.com/observatorium/api/logger"
)

// redirectTransport redirects all requests to the target host.
type redirectTransport struct {
	targetHost string
	transport  http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect request to mock server while keeping the path
	req.URL.Host = rt.targetHost
	req.URL.Scheme = "http"
	return rt.transport.RoundTrip(req)
}

func TestDiscoverOAuthEndpoints_OAuthEnabled(t *testing.T) {
	tenant := "tenant"
	logger := logger.NewLogger("warn", logger.LogFormatLogfmt, "")
	r := chi.NewMux()

	r.Get(openshift.OauthWellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{
            "authorization_endpoint": "https://oauth.example.com/authorize",
            "token_endpoint": "https://oauth.example.com/token"
        }`)); err != nil {
			t.Fatalf("failed to write response %v", err)
		}
	})

	mockAPIServer := httptest.NewServer(r)
	defer mockAPIServer.Close()

	mockURL, err := url.Parse(mockAPIServer.URL)
	if err != nil {
		t.Fatalf("failed to parse mock server URL: %v", err)
	}

	// Split host and port for KUBERNETES env vars
	host, port, err := net.SplitHostPort(mockURL.Host)
	if err != nil {
		t.Fatalf("failed to parse mock server address: %v", err)
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)

	retryCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_retries_total",
		Help: "Total number of OAuth discovery retries",
	},
		[]string{"tenant", "type"},
	)

	client := &http.Client{
		Transport: &redirectTransport{
			targetHost: mockURL.Host,
			transport:  http.DefaultTransport,
		},
	}

	b := backoff.New(context.TODO(), backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 0, // Retry indefinitely.
	})

	authURL, tokenURL, oauthEnabled := discoverOAuthEndpoints(client, logger, tenant, retryCounter, b)

	assert.NotNil(t, authURL)
	assert.NotNil(t, tokenURL)
	assert.True(t, oauthEnabled)
	assert.Equal(t, authURL.String(), "https://oauth.example.com/authorize")
	assert.Equal(t, tokenURL.String(), "https://oauth.example.com/token")
}

func TestDiscoverOAuthEndpoints_OAuthDisabled(t *testing.T) {
	tenant := "tenant"
	logger := logger.NewLogger("warn", logger.LogFormatLogfmt, "")
	r := chi.NewMux()

	r.Get(openshift.OauthWellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte("404 page not found")); err != nil {
			t.Fatalf("failed to write response %v", err)
		}
	})

	mockAPIServer := httptest.NewServer(r)
	defer mockAPIServer.Close()

	mockURL, err := url.Parse(mockAPIServer.URL)
	if err != nil {
		t.Fatalf("failed to parse mock server URL: %v", err)
	}

	// Split host and port for KUBERNETES env vars
	host, port, err := net.SplitHostPort(mockURL.Host)
	if err != nil {
		t.Fatalf("failed to parse mock server address: %v", err)
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)

	retryCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_retries_total",
		Help: "Total number of OAuth discovery retries",
	},
		[]string{"tenant", "type"},
	)

	client := &http.Client{
		Transport: &redirectTransport{
			targetHost: mockURL.Host,
			transport:  http.DefaultTransport,
		},
	}

	b := backoff.New(context.TODO(), backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 0, // Retry indefinitely.
	})

	authURL, tokenURL, oauthEnabled := discoverOAuthEndpoints(client, logger, tenant, retryCounter, b)

	assert.Nil(t, authURL)
	assert.Nil(t, tokenURL)
	assert.False(t, oauthEnabled)
}
