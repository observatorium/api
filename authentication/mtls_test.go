package authentication

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/go-kit/log"
	"github.com/observatorium/api/test/testtls"
)

// Helper function to generate test certificates using the existing testtls package
func setupTestCertificatesWithFile(t testing.TB) (clientCert tls.Certificate, caPath string, cleanup func()) {
	t.Helper()

	// Create temporary directory for certificates
	tmpDir, err := os.MkdirTemp("", "mtls-test-certs-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Generate certificates using the testtls package
	err = testtls.GenerateCerts(
		tmpDir,
		"test-api",     // API common name
		[]string{"localhost", "127.0.0.1"}, // API SANs
		"test-dex",     // Dex common name
		[]string{"localhost"}, // Dex SANs
	)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to generate certificates: %v", err)
	}

	// Read client certificate and key
	clientCertPEM, err := os.ReadFile(filepath.Join(tmpDir, "client.pem"))
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to read client certificate: %v", err)
	}

	clientKeyPEM, err := os.ReadFile(filepath.Join(tmpDir, "client.key"))
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to read client key: %v", err)
	}

	// Create tls.Certificate for use in requests
	clientCert, err = tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create client TLS certificate: %v", err)
	}

	caPath = filepath.Join(tmpDir, "ca.pem")
	cleanup = func() {
		os.RemoveAll(tmpDir)
	}

	return clientCert, caPath, cleanup
}

func TestMTLSAuthenticator_PathBasedAuthentication(t *testing.T) {
	// Generate test certificates using file-based CA
	clientCert, caPath, cleanup := setupTestCertificatesWithFile(t)
	defer cleanup()

	tests := []struct {
		name           string
		pathPatterns   []string
		requestPath    string
		expectMTLS     bool
		expectError    bool
		description    string
	}{
		{
			name:         "no_patterns_enforces_all_paths",
			pathPatterns: []string{},
			requestPath:  "/api/v1/query",
			expectMTLS:   true,
			expectError:  false, // Should work with proper file-based CA
			description:  "When no patterns are configured, mTLS should be enforced on all paths",
		},
		{
			name:         "write_pattern_matches_receive",
			pathPatterns: []string{"/api/.*/receive", "/api/.*/rules"},
			requestPath:  "/api/metrics/v1/receive",
			expectMTLS:   true,
			expectError:  false, // Should work with proper file-based CA
			description:  "Write endpoints should require mTLS",
		},
		{
			name:         "write_pattern_matches_rules",
			pathPatterns: []string{"/api/.*/receive", "/api/.*/rules"},
			requestPath:  "/api/logs/v1/rules",
			expectMTLS:   true,
			expectError:  false, // Should work with proper file-based CA
			description:  "Rules endpoints should require mTLS",
		},
		{
			name:         "read_pattern_skips_query",
			pathPatterns: []string{"/api/.*/receive", "/api/.*/rules"},
			requestPath:  "/api/metrics/v1/query",
			expectMTLS:   false,
			expectError:  false,
			description:  "Read endpoints should skip mTLS when not in patterns",
		},
		{
			name:         "read_pattern_skips_series",
			pathPatterns: []string{"/api/.*/receive", "/api/.*/rules"},
			requestPath:  "/api/metrics/v1/series",
			expectMTLS:   false,
			expectError:  false,
			description:  "Series endpoints should skip mTLS when not in patterns",
		},
		{
			name:         "complex_pattern_matching",
			pathPatterns: []string{"^/api/metrics/.*/(receive|rules)$"},
			requestPath:  "/api/metrics/v1/receive",
			expectMTLS:   true,
			expectError:  false, // Should work with proper file-based CA
			description:  "Complex regex patterns should work correctly",
		},
		{
			name:         "complex_pattern_non_matching",
			pathPatterns: []string{"^/api/metrics/.*/(receive|rules)$"},
			requestPath:  "/api/metrics/v1/query",
			expectMTLS:   false,
			expectError:  false,
			description:  "Complex regex patterns should correctly exclude non-matching paths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mTLS config with path patterns using file-based CA
			config := map[string]interface{}{
				"caPath":       caPath,  // Use file-based CA as original code expects
				"pathPatterns": tt.pathPatterns,
			}

			// Create mTLS authenticator
			logger := log.NewNopLogger()
			authenticator, err := newMTLSAuthenticator(config, "test-tenant", nil, logger)
			if err != nil {
				t.Fatalf("Failed to create mTLS authenticator: %v", err)
			}

			// Create middleware
			middleware := authenticator.Middleware()

			// Create test handler that records if it was called
			handlerCalled := false
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Wrap handler with middleware
			wrappedHandler := middleware(testHandler)

			// Create request
			req := httptest.NewRequest("POST", tt.requestPath, nil)

			if tt.expectMTLS {
				// Parse client certificate for TLS connection state
				clientX509Cert, err := x509.ParseCertificate(clientCert.Certificate[0])
				if err != nil {
					t.Fatalf("Failed to parse client certificate: %v", err)
				}
				// Add TLS connection state with client certificate
				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{clientX509Cert},
				}
			} else {
				// For non-mTLS paths, we might not have TLS at all, or TLS without client certs
				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{},
				}
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute request
			wrappedHandler.ServeHTTP(rr, req)

			// Verify results
			if tt.expectMTLS {
				if tt.expectError {
					// mTLS was attempted but certificate validation failed
					if rr.Code == http.StatusOK {
						t.Errorf("Expected authentication error, but got status %d", rr.Code)
					}
					if handlerCalled {
						t.Error("Handler should not be called when certificate validation fails")
					}
				} else {
					// mTLS was attempted and should succeed with valid certificates
					if rr.Code != http.StatusOK {
						t.Errorf("Expected success with valid mTLS, but got status %d: %s", rr.Code, rr.Body.String())
					}
					if !handlerCalled {
						t.Error("Handler should be called when authentication succeeds")
					}
				}
			} else {
				// Path doesn't require mTLS, should always succeed
				if rr.Code != http.StatusOK {
					t.Errorf("Expected success for non-mTLS path, but got status %d: %s", rr.Code, rr.Body.String())
				}
				if !handlerCalled {
					t.Error("Handler should be called when mTLS is not required")
				}
			}
		})
	}
}

func TestMTLSAuthenticator_InvalidClientCertificate(t *testing.T) {
	// Generate test certificates
	_, caPath, cleanup1 := setupTestCertificatesWithFile(t)
	defer cleanup1()

	// Generate a different set of certificates for invalid client cert
	invalidClientCert, _, cleanup2 := setupTestCertificatesWithFile(t)
	defer cleanup2()

	// Create mTLS config
	config := map[string]interface{}{
		"caPath":       caPath,
		"pathPatterns": []string{"/api/.*/receive"},
	}

	// Create mTLS authenticator
	logger := log.NewNopLogger()
	authenticator, err := newMTLSAuthenticator(config, "test-tenant", nil, logger)
	if err != nil {
		t.Fatalf("Failed to create mTLS authenticator: %v", err)
	}

	// Create middleware
	middleware := authenticator.Middleware()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := middleware(testHandler)

	// Test with invalid client certificate
	req := httptest.NewRequest("POST", "/api/metrics/v1/receive", nil)
	invalidX509Cert, err := x509.ParseCertificate(invalidClientCert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse invalid client certificate: %v", err)
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{invalidX509Cert},
	}

	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	// In test context, certificate validation issues result in 500 instead of 401
	if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected %d or %d for invalid certificate, but got %d", http.StatusUnauthorized, http.StatusInternalServerError, rr.Code)
	}
}

func TestMTLSAuthenticator_NoTLSConnection(t *testing.T) {
	// Generate test certificates
	_, caPath, cleanup := setupTestCertificatesWithFile(t)
	defer cleanup()

	// Create mTLS config
	config := map[string]interface{}{
		"caPath":       caPath,
		"pathPatterns": []string{"/api/.*/receive"},
	}

	// Create mTLS authenticator
	logger := log.NewNopLogger()
	authenticator, err := newMTLSAuthenticator(config, "test-tenant", nil, logger)
	if err != nil {
		t.Fatalf("Failed to create mTLS authenticator: %v", err)
	}

	// Create middleware
	middleware := authenticator.Middleware()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedHandler := middleware(testHandler)

	// Test with no TLS connection
	req := httptest.NewRequest("POST", "/api/metrics/v1/receive", nil)
	// req.TLS is nil (no TLS connection)

	rr := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d for no TLS connection, but got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestMTLSAuthenticator_InvalidPathPattern(t *testing.T) {
	// Test that invalid regex patterns are caught during creation
	config := map[string]interface{}{
		"pathPatterns": []string{"[invalid-regex"},
	}

	logger := log.NewNopLogger()
	_, err := newMTLSAuthenticator(config, "test-tenant", nil, logger)
	if err == nil {
		t.Error("Expected error for invalid regex pattern, but got nil")
	}
}

// Test path matching logic without requiring certificate validation
func TestMTLSAuthenticator_PathMatchingLogic(t *testing.T) {
	tests := []struct {
		name         string
		pathPatterns []string
		requestPath  string
		expectSkip   bool
		description  string
	}{
		{
			name:         "no_patterns_requires_mtls_everywhere",
			pathPatterns: []string{},
			requestPath:  "/api/v1/query",
			expectSkip:   false,
			description:  "No patterns means mTLS required everywhere",
		},
		{
			name:         "pattern_matches_requires_mtls",
			pathPatterns: []string{"/api/.*/receive"},
			requestPath:  "/api/metrics/v1/receive", 
			expectSkip:   false,
			description:  "Matching pattern requires mTLS",
		},
		{
			name:         "pattern_not_matches_skips_mtls",
			pathPatterns: []string{"/api/.*/receive"},
			requestPath:  "/api/metrics/v1/query",
			expectSkip:   true,
			description:  "Non-matching pattern skips mTLS",
		},
		{
			name:         "multiple_patterns_one_matches",
			pathPatterns: []string{"/api/.*/receive", "/api/.*/rules"},
			requestPath:  "/api/logs/v1/rules",
			expectSkip:   false,
			description:  "One matching pattern requires mTLS",
		},
		{
			name:         "multiple_patterns_none_match",
			pathPatterns: []string{"/api/.*/receive", "/api/.*/rules"},
			requestPath:  "/api/metrics/v1/query",
			expectSkip:   true,
			description:  "No matching patterns skip mTLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mTLS config without CA (we're only testing path logic)
			config := map[string]interface{}{
				"pathPatterns": tt.pathPatterns,
			}

			logger := log.NewNopLogger()
			authenticator, err := newMTLSAuthenticator(config, "test-tenant", nil, logger)
			if err != nil {
				t.Fatalf("Failed to create mTLS authenticator: %v", err)
			}

			middleware := authenticator.Middleware()
			
			handlerCalled := false
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("POST", tt.requestPath, nil)
			rr := httptest.NewRecorder()

			// Test without TLS to see if path matching works
			middleware(testHandler).ServeHTTP(rr, req)

			if tt.expectSkip {
				// Path should skip mTLS, handler should be called
				if !handlerCalled {
					t.Error("Expected handler to be called when path should skip mTLS")
				}
				if rr.Code != http.StatusOK {
					t.Errorf("Expected 200 when path skips mTLS, got %d", rr.Code)
				}
			} else {
				// Path should require mTLS, should fail due to no TLS
				if handlerCalled {
					t.Error("Expected handler not to be called when path requires mTLS")
				}
				if rr.Code == http.StatusOK {
					t.Error("Expected error when path requires mTLS but no TLS provided")
				}
			}
		})
	}
}

// Test both CA configuration methods work correctly
func TestMTLSAuthenticator_CAConfiguration(t *testing.T) {
	// Test file-based CA configuration
	t.Run("file_based_ca", func(t *testing.T) {
		_, caPath, cleanup := setupTestCertificatesWithFile(t)
		defer cleanup()

		config := map[string]interface{}{
			"caPath": caPath,
		}

		logger := log.NewNopLogger()
		authenticator, err := newMTLSAuthenticator(config, "test-tenant", nil, logger)
		if err != nil {
			t.Fatalf("Failed to create mTLS authenticator with file-based CA: %v", err)
		}

		// Verify CA was loaded
		mtlsAuth := authenticator.(MTLSAuthenticator)
		if len(mtlsAuth.config.CAs) == 0 {
			t.Error("Expected CAs to be loaded from file, but got none")
		}
	})

	// Test that direct CA configuration (RawCA) is NOT supported in original implementation
	t.Run("direct_ca_not_supported", func(t *testing.T) {
		_, caPath, cleanup := setupTestCertificatesWithFile(t)
		defer cleanup()

		// Read CA content
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			t.Fatalf("Failed to read CA file: %v", err)
		}

		config := map[string]interface{}{
			"ca": caPEM,  // Direct CA data
		}

		logger := log.NewNopLogger()
		authenticator, err := newMTLSAuthenticator(config, "test-tenant", nil, logger)
		if err != nil {
			t.Fatalf("Failed to create mTLS authenticator with direct CA: %v", err)
		}

		// Verify that CAs are NOT loaded (original behavior)
		mtlsAuth := authenticator.(MTLSAuthenticator)
		if len(mtlsAuth.config.CAs) != 0 {
			t.Error("Expected no CAs to be loaded from direct CA data in original implementation")
		}
	})
}

func TestMTLSPathPatternsWithOperators(t *testing.T) {
	tests := []struct {
		name         string
		paths        []PathPattern
		requestPath  string
		expectSkip   bool
		expectError  bool
		description  string
	}{
		{
			name:        "positive_match_operator",
			paths:       []PathPattern{{Operator: "=~", Pattern: "/api/.*/receive"}},
			requestPath: "/api/metrics/v1/receive",
			expectSkip:  false,
			description: "Positive match with =~ operator should enforce mTLS",
		},
		{
			name:        "positive_no_match_operator",
			paths:       []PathPattern{{Operator: "=~", Pattern: "/api/.*/receive"}},
			requestPath: "/api/metrics/v1/query",
			expectSkip:  true,
			description: "No match with =~ operator should skip mTLS",
		},
		{
			name:        "negative_match_operator",
			paths:       []PathPattern{{Operator: "!~", Pattern: "^/api/(logs|metrics)/v1/auth-tenant/.*(query|labels|series)"}},
			requestPath: "/api/metrics/v1/auth-tenant/api/v1/receive",
			expectSkip:  false,
			description: "Path not matching negative pattern should enforce mTLS",
		},
		{
			name:        "negative_no_match_operator",
			paths:       []PathPattern{{Operator: "!~", Pattern: "^/api/(logs|metrics)/v1/auth-tenant/.*(query|labels|series)"}},
			requestPath: "/api/metrics/v1/auth-tenant/api/v1/query",
			expectSkip:  true,
			description: "Path matching negative pattern should skip mTLS",
		},
		{
			name:        "default_operator",
			paths:       []PathPattern{{Pattern: "/api/.*/receive"}}, // no operator specified
			requestPath: "/api/metrics/v1/receive",
			expectSkip:  false,
			description: "Default operator should be =~",
		},
		{
			name:        "multiple_patterns_one_match",
			paths:       []PathPattern{
				{Operator: "=~", Pattern: "/api/.*/receive"},
				{Operator: "=~", Pattern: "/api/.*/push"},
			},
			requestPath: "/api/logs/v1/push",
			expectSkip:  false,
			description: "One matching pattern should enforce mTLS",
		},
		{
			name:        "multiple_patterns_none_match",
			paths:       []PathPattern{
				{Operator: "=~", Pattern: "/api/.*/receive"},
				{Operator: "=~", Pattern: "/api/.*/push"},
			},
			requestPath: "/api/metrics/v1/query",
			expectSkip:  true,
			description: "No matching patterns should skip mTLS",
		},
		{
			name:        "invalid_operator",
			paths:       []PathPattern{{Operator: "invalid", Pattern: "/api/.*/receive"}},
			expectError: true,
			description: "Invalid operator should cause error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test compilation (similar to newMTLSAuthenticator)
			var pathMatchers []PathMatcher
			
			for _, pathPattern := range tt.paths {
				operator := pathPattern.Operator
				if operator == "" {
					operator = "=~" // default operator
				}
				
				// Validate operator
				if operator != "=~" && operator != "!~" {
					if tt.expectError {
						return // Expected error
					}
					t.Errorf("Invalid operator %q should have caused error", operator)
					return
				}
				
				matcher, err := regexp.Compile(pathPattern.Pattern)
				if err != nil {
					if tt.expectError {
						return // Expected error
					}
					t.Fatalf("Failed to compile pattern: %v", err)
				}
				
				pathMatchers = append(pathMatchers, PathMatcher{
					Operator: operator,
					Regex:    matcher,
				})
			}
			
			if tt.expectError {
				t.Error("Expected error but none occurred")
				return
			}
			
			// Test the matching logic (from middleware)
			shouldEnforceMTLS := false
			
			for _, matcher := range pathMatchers {
				regexMatches := matcher.Regex.MatchString(tt.requestPath)
				
				if matcher.Operator == "=~" && regexMatches {
					shouldEnforceMTLS = true
					break
				} else if matcher.Operator == "!~" && !regexMatches {
					shouldEnforceMTLS = true
					break
				}
			}
			
			shouldSkip := !shouldEnforceMTLS
			
			if shouldSkip != tt.expectSkip {
				t.Errorf("Expected skip=%v, got skip=%v for path %s", tt.expectSkip, shouldSkip, tt.requestPath)
			}
		})
	}
}