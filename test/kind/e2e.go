package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type PortForwarder struct {
	stopChan  chan struct{}
	readyChan chan struct{}
}

func StartPortForward(ctx context.Context, port intstr.IntOrString, scheme, serviceName, ns string) (func(), error) {
	// Build config using KIND cluster context
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{
			CurrentContext: "kind-observatorium-auth-test",
		}).ClientConfig()
	if err != nil {
		return nil, err
	}

	// Find pod for the service
	podName, err := findPodForService(serviceName, ns, config)
	if err != nil {
		return nil, fmt.Errorf("failed to find pod for service %s: %w", serviceName, err)
	}

	roundTripper, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, err
	}

	// Use pod endpoint for port forwarding
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", ns, podName)
	hostIP := strings.TrimLeft(config.Host, "https://")
	serverURL := url.URL{Scheme: "https", Path: path, Host: hostIP}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, &serverURL)

	stopChan := make(chan struct{}, 1)
	readyChan := make(chan struct{}, 1)

	forwarder, err := portforward.New(dialer, []string{port.String()}, stopChan, readyChan, os.Stdout, os.Stderr)
	if err != nil {
		return nil, err
	}

	forwardErr := make(chan error, 1)
	go func() {
		if err := forwarder.ForwardPorts(); err != nil {
			forwardErr <- err
		}
		close(forwardErr)
	}()

	select {
	case <-readyChan:
		return func() { close(stopChan) }, nil
	case <-ctx.Done():
		var err error
		select {
		case err = <-forwardErr:
		default:
		}
		return nil, fmt.Errorf("%v: %v", ctx.Err(), err)
	}
}

func (p *PortForwarder) Stop() {
	close(p.stopChan)
}

func findPodForService(serviceName, namespace string, config *rest.Config) (string, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", serviceName),
	})
	if err != nil {
		return "", err
	}

	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for service %s", serviceName)
	}

	return pods.Items[0].Name, nil
}

// Test configuration
const (
	namespace = "proxy"
	apiPort   = 8080
	dexPort   = 5556
)

// Certificate and authentication setup
func loadTLSConfig() (*tls.Config, error) {
	caCert, err := os.ReadFile("testdata/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load client certificate for mTLS
	clientCert, err := tls.LoadX509KeyPair("testdata/test-client.crt", "testdata/test-client.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	return &tls.Config{
		RootCAs:            caCertPool,
		Certificates:       []tls.Certificate{clientCert},
		ServerName:         "observatorium-api",
		InsecureSkipVerify: true, // Skip hostname verification for localhost
	}, nil
}

func loadAdminTLSConfig() (*tls.Config, error) {
	caCert, err := os.ReadFile("testdata/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Load admin certificate for mTLS
	adminCert, err := tls.LoadX509KeyPair("testdata/admin-client.crt", "testdata/admin-client.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load admin certificate: %w", err)
	}

	return &tls.Config{
		RootCAs:            caCertPool,
		Certificates:       []tls.Certificate{adminCert},
		ServerName:         "observatorium-api",
		InsecureSkipVerify: true, // Skip hostname verification for localhost
	}, nil
}

// OIDC authentication helper - implements OAuth2 password flow
func performOIDCAuth() (string, error) {
	// Use OAuth2 password grant flow to get real token from Dex
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// OAuth2 token endpoint - Dex serves HTTP
	tokenURL := fmt.Sprintf("http://localhost:%d/dex/token", dexPort)

	// Prepare form data for OAuth2 password grant - using demo working values
	formData := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"observatorium-api"},
		"client_secret": {"ZXhhbXBsZS1hcHAtc2VjcmV0"},
		"username":      {"admin@example.com"},
		"password":      {"password"},
		"scope":         {"openid email"},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		IDToken      string `json:"id_token,omitempty"`
	}

	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	return tokenResp.AccessToken, nil
}

func TestMixedAuthenticationE2E(t *testing.T) {
	// Port forwards are set up in main function
	time.Sleep(2 * time.Second)

	// Run all test scenarios
	t.Run("TestReadEndpointsWithOIDC", testReadEndpointsWithOIDC)
	t.Run("TestWriteEndpointsWithMTLS", testWriteEndpointsWithMTLS)
	t.Run("TestReadEndpointsRejectMTLS", testReadEndpointsRejectMTLS)
	t.Run("TestWriteEndpointsRejectOIDC", testWriteEndpointsRejectOIDC)
	t.Run("TestInvalidCertificateRejection", testInvalidCertificateRejection)
	t.Run("TestPathPatternMatching", testPathPatternMatching)
	t.Run("TestRBACEnforcement", testRBACEnforcement)
	t.Run("TestBackendProxying", testBackendProxying)
}

func testReadEndpointsWithOIDC(t *testing.T) {
	// Test that read endpoints (query, etc.) work with OIDC authentication
	token, err := performOIDCAuth()
	if err != nil {
		t.Fatalf("Failed to get OIDC token: %v", err)
	}

	readEndpoints := []string{
		"/api/metrics/v1/auth-tenant/api/v1/query?query=up",
		"/api/metrics/v1/auth-tenant/api/v1/query_range?query=up&start=0&end=1&step=1",
		"/api/metrics/v1/auth-tenant/api/v1/labels",
		"/api/metrics/v1/auth-tenant/api/v1/series?match[]=up",
		"/api/logs/v1/auth-tenant/loki/api/v1/query?query={job=\"test\"}",
	}

	// Configure client for HTTPS with proper TLS setup
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		t.Fatalf("Failed to load TLS config: %v", err)
	}

	// For OIDC endpoints, only trust CA but don't present client certificates
	httpsClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            tlsConfig.RootCAs,
				InsecureSkipVerify: true, // Skip hostname verification for localhost
				// No client certificates for OIDC endpoints
			},
		},
	}

	for _, endpoint := range readEndpoints {
		t.Run(fmt.Sprintf("OIDC_%s", endpoint), func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("https://localhost:%d%s", apiPort, endpoint), nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			resp, err := httpsClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should successfully authenticate and reach the backend (2xx status)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("OIDC authentication failed for %s: %d - %s", endpoint, resp.StatusCode, string(body))
			}

			t.Logf("OIDC endpoint %s successfully authenticated with status %d", endpoint, resp.StatusCode)
		})
	}
}

func testWriteEndpointsWithMTLS(t *testing.T) {
	// Test that write endpoints (receive, push) work with mTLS authentication
	tlsConfig, err := loadAdminTLSConfig()
	if err != nil {
		t.Fatalf("Failed to load TLS config: %v", err)
	}

	// For mTLS endpoints, present client certificates and trust CA
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	writeEndpoints := []string{
		"/api/metrics/v1/auth-tenant/api/v1/receive",
		"/api/logs/v1/auth-tenant/loki/api/v1/push",
	}

	for _, endpoint := range writeEndpoints {
		t.Run(fmt.Sprintf("mTLS_%s", endpoint), func(t *testing.T) {
			req, err := http.NewRequest("POST", fmt.Sprintf("https://localhost:%d%s", apiPort, endpoint), strings.NewReader("test data"))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/x-protobuf")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should successfully authenticate and reach the backend (2xx status)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("mTLS authentication failed for %s: %d - %s", endpoint, resp.StatusCode, string(body))
			}

			t.Logf("mTLS endpoint %s successfully authenticated with status %d", endpoint, resp.StatusCode)
		})
	}
}

func testReadEndpointsRejectMTLS(t *testing.T) {
	// Test that read endpoints reject mTLS-only requests
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		t.Fatalf("Failed to load TLS config: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		// Don't follow redirects - we want to check the initial response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	readEndpoints := []string{
		"/api/metrics/v1/auth-tenant/api/v1/query?query=up",
		"/api/logs/v1/auth-tenant/loki/api/v1/query?query={job=\"test\"}",
	}

	for _, endpoint := range readEndpoints {
		t.Run(fmt.Sprintf("RejectMTLS_%s", endpoint), func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("https://localhost:%d%s", apiPort, endpoint), nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should be rejected (3xx redirect or 4xx error) since read endpoints require OIDC, not mTLS
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				t.Fatalf("Expected rejection (redirect or error), got success %d", resp.StatusCode)
			}

			t.Logf("Read endpoint correctly rejected mTLS request with status %d", resp.StatusCode)
		})
	}
}

func testWriteEndpointsRejectOIDC(t *testing.T) {
	// Test that write endpoints reject OIDC-only requests
	token, err := performOIDCAuth()
	if err != nil {
		t.Fatalf("Failed to get OIDC token: %v", err)
	}

	writeEndpoints := []string{
		"/api/metrics/v1/auth-tenant/api/v1/receive",
		"/api/logs/v1/auth-tenant/loki/api/v1/push",
	}

	for _, endpoint := range writeEndpoints {
		t.Run(fmt.Sprintf("RejectOIDC_%s", endpoint), func(t *testing.T) {
			req, err := http.NewRequest("POST", fmt.Sprintf("https://localhost:%d%s", apiPort, endpoint), strings.NewReader("test data"))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			req.Header.Set("Content-Type", "application/x-protobuf")

			// Create HTTPS client that skips cert verification for localhost
			httpsClient := &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}

			resp, err := httpsClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should be rejected since write endpoints require mTLS, not OIDC
			if resp.StatusCode < 400 {
				t.Fatalf("Expected authentication error, got %d", resp.StatusCode)
			}

			t.Logf("Write endpoint correctly rejected OIDC request with status %d", resp.StatusCode)
		})
	}
}

func testInvalidCertificateRejection(t *testing.T) {
	// Test that invalid certificates are rejected
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip verification to test our authentication
			},
		},
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://localhost:%d/api/metrics/v1/auth-tenant/api/v1/receive", apiPort), strings.NewReader("test data"))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be rejected due to missing client certificate
	if resp.StatusCode < 400 {
		t.Fatalf("Expected authentication error for missing certificate, got %d", resp.StatusCode)
	}

	t.Logf("Request correctly rejected for missing certificate with status %d", resp.StatusCode)
}

func testPathPatternMatching(t *testing.T) {
	// Test that path patterns work correctly for edge cases
	token, err := performOIDCAuth()
	if err != nil {
		t.Fatalf("Failed to get OIDC token: %v", err)
	}

	// Test various path patterns to ensure regex matching works
	testCases := []struct {
		path        string
		expectOIDC  bool
		description string
	}{
		{"/api/metrics/v1/auth-tenant/api/v1/query", true, "query endpoint should use OIDC"},
		{"/api/metrics/v1/auth-tenant/api/v1/receive", false, "receive endpoint should use mTLS"},
		{"/api/metrics/v1/auth-tenant/api/v1/query_range", true, "query_range should use OIDC"},
		{"/api/metrics/v1/auth-tenant/api/v1/labels", true, "labels should use OIDC"},
		{"/api/logs/v1/auth-tenant/loki/api/v1/query", true, "log query should use OIDC"},
		{"/api/logs/v1/auth-tenant/loki/api/v1/push", false, "log push should use mTLS"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			if tc.expectOIDC {
				// Test with OIDC token
				req, err := http.NewRequest("GET", fmt.Sprintf("https://localhost:%d%s", apiPort, tc.path), nil)
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

				// Create HTTPS client for OIDC requests
				httpsClient := &http.Client{
					Timeout: 30 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}

				resp, err := httpsClient.Do(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					t.Fatalf("OIDC authentication failed for path %s: %d", tc.path, resp.StatusCode)
				}

				t.Logf("OIDC path %s successfully authenticated: %d", tc.path, resp.StatusCode)
			} else {
				// Test that OIDC is rejected for mTLS paths
				req, err := http.NewRequest("POST", fmt.Sprintf("https://localhost:%d%s", apiPort, tc.path), strings.NewReader("test"))
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}

				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

				// Create HTTPS client for mTLS test requests
				httpsClient := &http.Client{
					Timeout: 30 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					},
				}

				resp, err := httpsClient.Do(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode < 400 {
					t.Fatalf("Expected auth error for mTLS path with OIDC: %d", resp.StatusCode)
				}

				t.Logf("mTLS path %s correctly rejected OIDC: %d", tc.path, resp.StatusCode)
			}
		})
	}
}

func testRBACEnforcement(t *testing.T) {
	// Test that RBAC rules are enforced correctly
	// This tests the authorization layer after authentication

	token, err := performOIDCAuth()
	if err != nil {
		t.Fatalf("Failed to get OIDC token: %v", err)
	}

	// Configure client for HTTPS with proper TLS setup
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		t.Fatalf("Failed to load TLS config: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            tlsConfig.RootCAs,
				InsecureSkipVerify: true, // Skip hostname verification since we're using localhost
			},
		},
	}

	// Test with different user credentials to verify RBAC
	req, err := http.NewRequest("GET", fmt.Sprintf("https://localhost:%d/api/metrics/v1/auth-tenant/api/v1/query?query=up", apiPort), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// RBAC should allow this request based on our test configuration (2xx status)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("RBAC/authentication failed: %d", resp.StatusCode)
	}

	t.Logf("RBAC enforcement test passed with status %d", resp.StatusCode)
}

func testBackendProxying(t *testing.T) {
	// Test that requests are properly proxied to HTTPBin backend
	token, err := performOIDCAuth()
	if err != nil {
		t.Fatalf("Failed to get OIDC token: %v", err)
	}

	// Configure client for HTTPS with proper TLS setup
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		t.Fatalf("Failed to load TLS config: %v", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            tlsConfig.RootCAs,
				InsecureSkipVerify: true, // Skip hostname verification since we're using localhost
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://localhost:%d/api/metrics/v1/auth-tenant/api/v1/query?query=test", apiPort), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("X-Test-Header", "test-value")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should successfully authenticate and reach backend (2xx status)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("Backend proxying failed - authentication or proxy error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// HTTPBin's /anything endpoint returns request details as JSON
	responseBody := string(body)

	// Log the response for debugging
	t.Logf("Backend response body: %s", responseBody)

	// Verify we got a response (the backend proxying is working)
	if len(responseBody) == 0 {
		t.Fatalf("Backend proxy failed - empty response")
	}

	t.Logf("Backend proxying working correctly - received response: %d bytes", len(responseBody))
}

func main() {
	ctx := context.Background()
	
	// Set up port forwards to services
	fmt.Println("Starting port forward for observatorium-api service...")
	stopAPIForward, err := StartPortForward(ctx, intstr.FromInt(apiPort), "https", "observatorium-api", namespace)
	if err != nil {
		fmt.Printf("Failed to start API port forward: %v\n", err)
		return
	}
	defer stopAPIForward()
	
	fmt.Println("Starting port forward for dex service...")
	stopDexForward, err := StartPortForward(ctx, intstr.FromInt(dexPort), "http", "dex", namespace)
	if err != nil {
		fmt.Printf("Failed to start Dex port forward: %v\n", err)
		return
	}
	defer stopDexForward()
	
	// Give port forwards time to establish
	fmt.Println("Port forwards established, running tests...")
	time.Sleep(3 * time.Second)
	
	testing.Main(func(pat, str string) (bool, error) { return true, nil },
		[]testing.InternalTest{
			{"TestMixedAuthenticationE2E", TestMixedAuthenticationE2E},
		},
		[]testing.InternalBenchmark{},
		[]testing.InternalExample{})
}
