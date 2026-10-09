//go:build integration

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
)

// PathBasedTestUser represents a test user with specific path-based permissions
type PathBasedTestUser struct {
	Name         string
	CertFile     string
	KeyFile      string
	Tenant       string
	AllowedPaths []string
	DeniedPaths  []string
}

func TestPathBasedRBAC(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName("path-rbac-test"))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	// Prepare configuration and certificates including path-based ones
	preparePathBasedConfigsAndCerts(t, e)

	// Start base services (without rate limiter for simplicity)
	_, _, _ = startBaseServices(t, e, metrics)

	// Start backend services for testing
	readEndpoint, writeEndpoint, _ := startServicesForMetrics(t, e)
	logsEndpoint := startServicesForLogs(t, e)

	// Create Observatorium API with path-based RBAC configuration
	api, err := newPathBasedObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withLogsEndpoints("http://"+logsEndpoint, "http://"+logsEndpoint),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	// Define test users with different path permissions
	testUsers := []PathBasedTestUser{
		{
			Name:     "admin",
			CertFile: "admin.crt",
			KeyFile:  "admin.key",
			Tenant:   "test",
			AllowedPaths: []string{
				"/api/v1/query",
				"/api/v1/query_range",
				"/api/v1/receive",
				"/api/v1/series",
				"/api/v1/labels",
			},
			DeniedPaths: []string{}, // Admin should have access to everything
		},
		{
			Name:     "query-user",
			CertFile: "query-user.crt",
			KeyFile:  "query-user.key",
			Tenant:   "test",
			AllowedPaths: []string{
				"/api/v1/query",
				"/api/v1/query_range",
			},
			DeniedPaths: []string{
				"/api/v1/receive",
				"/api/v1/series",
				"/api/v1/labels",
			},
		},
		{
			Name:     "write-user",
			CertFile: "write-user.crt",
			KeyFile:  "write-user.key",
			Tenant:   "test",
			AllowedPaths: []string{
				"/api/v1/receive",
			},
			DeniedPaths: []string{
				"/api/v1/query",
				"/api/v1/query_range",
				"/api/v1/series",
				"/api/v1/labels",
			},
		},
		{
			Name:     "readonly-user",
			CertFile: "test.crt",
			KeyFile:  "test.key",
			Tenant:   "test",
			AllowedPaths: []string{
				"/api/v1/query",
				"/api/v1/query_range",
				"/api/v1/series",
				"/api/v1/labels",
			},
			DeniedPaths: []string{
				"/api/v1/receive",
			},
		},
	}

	// Test each user's access patterns
	for _, user := range testUsers {
		t.Run(fmt.Sprintf("user_%s", user.Name), func(t *testing.T) {
			testUserPathAccess(t, e, api, user)
		})
	}

	// Test cross-tenant access (should be denied)
	t.Run("cross_tenant_access", func(t *testing.T) {
		testCrossTenantAccess(t, e, api, testUsers[0]) // Use admin user but wrong tenant
	})

	// Test no certificate access (should be denied)
	t.Run("no_certificate_access", func(t *testing.T) {
		testNoCertificateAccess(t, api)
	})
}

func preparePathBasedConfigsAndCerts(t *testing.T, e e2e.Environment) {
	// Generate certificates for path-based RBAC testing
	generatePathBasedCerts(t, e)

	// Copy enhanced RBAC configuration
	copyPathBasedConfigs(t, e)
}

func generatePathBasedCerts(t *testing.T, e e2e.Environment) {
	certsDir := filepath.Join(e.SharedDir(), certsSharedDir)

	// Generate server certificates
	testutil.Ok(t, generateServerCert(certsDir, "observatorium-api"))

	// Generate client certificates for different users
	users := []struct {
		name string
		cn   string
		ou   string
	}{
		{"admin", "admin@example.com", "admins"},
		{"test", "test@example.com", "users"},
		{"query-user", "query@example.com", "query-users"},
		{"write-user", "write@example.com", "write-users"},
		{"logs-reader", "logs-reader@example.com", "logs-readers"},
	}

	for _, user := range users {
		testutil.Ok(t, generateClientCert(certsDir, user.name, user.cn, user.ou))
	}
}

func copyPathBasedConfigs(t *testing.T, e e2e.Environment) {
	configDir := filepath.Join(e.SharedDir(), configSharedDir)

	// Copy base configuration
	testutil.Ok(t, copyFile("../config", configDir))

	// Copy path-based RBAC configuration
	testutil.Ok(t, copyFile("../../demo/rbac-with-paths.yaml", filepath.Join(configDir, "rbac.yaml")))

	// Copy enhanced OPA policy
	testutil.Ok(t, copyFile("../../demo/observatorium-path-based.rego", filepath.Join(configDir, "observatorium.rego")))
}

func testUserPathAccess(t *testing.T, e e2e.Environment, api e2e.Runnable, user PathBasedTestUser) {
	client := createTLSClient(t, e, user.CertFile, user.KeyFile)
	baseURL := fmt.Sprintf("https://%s", api.InternalEndpoint("https"))

	// Test allowed paths
	for _, path := range user.AllowedPaths {
		t.Run(fmt.Sprintf("allowed_%s", strings.ReplaceAll(path, "/", "_")), func(t *testing.T) {
			testEndpointAccess(t, client, baseURL, path, user.Tenant, true)
		})
	}

	// Test denied paths
	for _, path := range user.DeniedPaths {
		t.Run(fmt.Sprintf("denied_%s", strings.ReplaceAll(path, "/", "_")), func(t *testing.T) {
			testEndpointAccess(t, client, baseURL, path, user.Tenant, false)
		})
	}
}

func testCrossTenantAccess(t *testing.T, e e2e.Environment, api e2e.Runnable, user PathBasedTestUser) {
	client := createTLSClient(t, e, user.CertFile, user.KeyFile)
	baseURL := fmt.Sprintf("https://%s", api.InternalEndpoint("https"))

	// Try to access with a different tenant (should be denied)
	wrongTenant := "unauthorized-tenant"
	path := "/api/v1/query"

	resp, err := makeRequest(client, baseURL, path, wrongTenant, "GET", nil)
	testutil.Ok(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Errorf("Expected access denial for cross-tenant request, but got status %d", resp.StatusCode)
	}
}

func testNoCertificateAccess(t *testing.T, api e2e.Runnable) {
	// Create client without certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}

	baseURL := fmt.Sprintf("https://%s", api.InternalEndpoint("https"))
	path := "/api/v1/query"
	tenant := "test"

	resp, err := makeRequest(client, baseURL, path, tenant, "GET", nil)
	testutil.Ok(t, err)
	defer resp.Body.Close()

	// Should be denied (4xx status code)
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("Expected 4xx status for no certificate access, but got %d", resp.StatusCode)
	}
}

func testEndpointAccess(t *testing.T, client *http.Client, baseURL, path, tenant string, shouldAllow bool) {
	var method string
	var body io.Reader

	// Determine HTTP method based on path
	if strings.Contains(path, "receive") {
		method = "POST"
		body = strings.NewReader("test_metric 1")
	} else {
		method = "GET"
		body = nil
	}

	resp, err := makeRequest(client, baseURL, path, tenant, method, body)
	testutil.Ok(t, err)
	defer resp.Body.Close()

	if shouldAllow {
		if resp.StatusCode >= 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Errorf("Expected access to be allowed for path %s, but got status %d: %s", 
				path, resp.StatusCode, string(bodyBytes))
		}
	} else {
		if resp.StatusCode < 400 {
			t.Errorf("Expected access to be denied for path %s, but got status %d", path, resp.StatusCode)
		}
	}
}

func createTLSClient(t *testing.T, e e2e.Environment, certFile, keyFile string) *http.Client {
	certsDir := filepath.Join(e.SharedDir(), certsSharedDir)
	
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certsDir, certFile),
		filepath.Join(certsDir, keyFile),
	)
	testutil.Ok(t, err)

	// Load CA certificate
	caCert, err := os.ReadFile(filepath.Join(certsDir, "ca.crt"))
	testutil.Ok(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}
}

func makeRequest(client *http.Client, baseURL, path, tenant, method string, body io.Reader) (*http.Response, error) {
	fullURL := baseURL + path
	if method == "GET" && strings.Contains(path, "query") {
		// Add query parameter for metrics endpoints
		fullURL += "?query=up"
	}

	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Tenant", tenant)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-protobuf")
	}

	return client.Do(req)
}

// Helper function to create Observatorium API service with path-based RBAC
func newPathBasedObservatoriumAPIService(e e2e.Environment, options ...observatoriumAPIOption) (e2e.Runnable, error) {
	config := observatoriumAPIConfig{
		image:              "observatorium-api:latest",
		listenPort:         8080,
		internalListenPort: 8081,
		logLevel:           "debug",
	}

	for _, opt := range options {
		opt(&config)
	}

	args := []string{
		"--web.listen=0.0.0.0:" + fmt.Sprintf("%d", config.listenPort),
		"--web.internal.listen=0.0.0.0:" + fmt.Sprintf("%d", config.internalListenPort),
		"--log.level=" + config.logLevel,
		"--tenants.config=" + filepath.Join("/shared", configSharedDir, "tenants.yaml"),
		"--rbac.config=" + filepath.Join("/shared", configSharedDir, "rbac.yaml"),
	}

	if config.tlsServerCertFile != "" && config.tlsServerKeyFile != "" {
		args = append(args,
			"--tls.server.cert-file="+config.tlsServerCertFile,
			"--tls.server.private-key-file="+config.tlsServerKeyFile,
		)
	}

	if config.tlsServerCAFile != "" {
		args = append(args, "--tls.ca-file="+config.tlsServerCAFile)
	}

	// Add OPA configuration for path-based authorization
	args = append(args, "--opa.url=http://127.0.0.1:8181/v1/data/observatorium/allow")

	// Add metrics endpoints
	if config.metricsReadEndpoint != "" {
		args = append(args, "--metrics.read.endpoint="+config.metricsReadEndpoint)
	}
	if config.metricsWriteEndpoint != "" {
		args = append(args, "--metrics.write.endpoint="+config.metricsWriteEndpoint)
	}

	// Add logs endpoints
	if config.logsReadEndpoint != "" {
		args = append(args, "--logs.read.endpoint="+config.logsReadEndpoint)
	}
	if config.logsWriteEndpoint != "" {
		args = append(args, "--logs.write.endpoint="+config.logsWriteEndpoint)
	}

	return e2e.NewRunnable("observatorium-api").WithPorts(
		map[string]int{"https": config.listenPort, "http": config.internalListenPort},
	).Init(e2e.StartOptions{
		Image:     config.image,
		Command:   e2e.NewCommand("observatorium-api", args...),
		Readiness: e2e.NewHTTPReadinessProbe("http", "/metrics", 200, 200),
		User:      "65534", // nobody
	}), nil
}

// Helper functions for file operations
func generateServerCert(certsDir, hostname string) error {
	// Implementation would generate server certificate
	// For now, this is a placeholder - would need to integrate with testtls package
	return nil
}

func generateClientCert(certsDir, name, cn, ou string) error {
	// Implementation would generate client certificate with specific CN and OU
	// For now, this is a placeholder - would need to integrate with testtls package
	return nil
}

func copyFile(src, dst string) error {
	// Implementation would copy file/directory
	// For now, this is a placeholder
	return nil
}

func startServicesForLogs(t *testing.T, e e2e.Environment) string {
	// Start a mock logs service similar to metrics
	// For now, return a placeholder endpoint
	return "loki:3100"
}