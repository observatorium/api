package authentication

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/go-kit/log"
	"github.com/mitchellh/mapstructure"
)

func TestOIDCPathMatching(t *testing.T) {
	tests := []struct {
		name         string
		pathPatterns []string
		requestPath  string
		expectSkip   bool
		description  string
	}{
		{
			name:         "empty_patterns_enforces_all",
			pathPatterns: []string{},
			requestPath:  "/api/v1/query",
			expectSkip:   false,
			description:  "Empty patterns should enforce OIDC on all paths",
		},
		{
			name:         "read_pattern_matches_query",
			pathPatterns: []string{"/api/.*/query", "/api/.*/series"},
			requestPath:  "/api/metrics/v1/query",
			expectSkip:   false,
			description:  "Query path should match read patterns",
		},
		{
			name:         "read_pattern_matches_series",
			pathPatterns: []string{"/api/.*/query", "/api/.*/series"},
			requestPath:  "/api/logs/v1/series",
			expectSkip:   false,
			description:  "Series path should match read patterns",
		},
		{
			name:         "write_path_skipped",
			pathPatterns: []string{"/api/.*/query", "/api/.*/series"},
			requestPath:  "/api/metrics/v1/receive",
			expectSkip:   true,
			description:  "Write path should be skipped when not in patterns",
		},
		{
			name:         "complex_regex_matching",
			pathPatterns: []string{"^/api/metrics/.*/(query|series)$"},
			requestPath:  "/api/metrics/v1/query",
			expectSkip:   false,
			description:  "Complex regex should match correctly",
		},
		{
			name:         "complex_regex_non_matching",
			pathPatterns: []string{"^/api/metrics/.*/(query|series)$"},
			requestPath:  "/api/logs/v1/query",
			expectSkip:   true,
			description:  "Complex regex should exclude non-matching paths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a testable version of the OIDC path matching logic
			pathMatchers := make([]*regexp.Regexp, 0, len(tt.pathPatterns))
			for _, pattern := range tt.pathPatterns {
				matcher, err := regexp.Compile(pattern)
				if err != nil {
					t.Fatalf("Failed to compile pattern %q: %v", pattern, err)
				}
				pathMatchers = append(pathMatchers, matcher)
			}

			// Test the path matching logic (extracted from oidcAuthenticator.Middleware)
			shouldSkip := false
			if len(pathMatchers) > 0 {
				pathMatches := false
				for _, matcher := range pathMatchers {
					if matcher.MatchString(tt.requestPath) {
						pathMatches = true
						break
					}
				}
				shouldSkip = !pathMatches
			}

			if shouldSkip != tt.expectSkip {
				t.Errorf("Expected skip=%v, got skip=%v for path %q with patterns %v", 
					tt.expectSkip, shouldSkip, tt.requestPath, tt.pathPatterns)
			}
		})
	}
}

func TestOIDCConfigPathPatternsIntegration(t *testing.T) {
	// Test that path patterns are correctly passed to the OIDC authenticator config
	tests := []struct {
		name         string
		configData   map[string]interface{}
		expectError  bool
		expectPaths  []string
		description  string
	}{
		{
			name: "valid_path_patterns",
			configData: map[string]interface{}{
				"pathPatterns": []string{"/api/.*/query", "/api/.*/series"},
				"clientID":     "test-client",
				"issuerURL":    "https://example.com",
			},
			expectError: false,
			expectPaths: []string{"/api/.*/query", "/api/.*/series"},
			description: "Valid path patterns should be accepted",
		},
		{
			name: "empty_path_patterns", 
			configData: map[string]interface{}{
				"pathPatterns": []string{},
				"clientID":     "test-client",
				"issuerURL":    "https://example.com",
			},
			expectError: false,
			expectPaths: []string{},
			description: "Empty path patterns should be accepted",
		},
		{
			name: "missing_path_patterns",
			configData: map[string]interface{}{
				"clientID":  "test-client",
				"issuerURL": "https://example.com",
			},
			expectError: false,
			expectPaths: nil,
			description: "Missing path patterns should default to nil/empty",
		},
		{
			name: "invalid_regex_pattern",
			configData: map[string]interface{}{
				"pathPatterns": []string{"[invalid-regex"},
				"clientID":     "test-client",
				"issuerURL":    "https://example.com",
			},
			expectError: true,
			description: "Invalid regex should cause creation to fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the config decoding and pattern compilation
			var config oidcConfig
			err := mapstructure.Decode(tt.configData, &config)
			if err != nil {
				if !tt.expectError {
					t.Errorf("Unexpected error decoding config: %v", err)
				}
				return
			}

			// Test path pattern compilation (this is what happens in newOIDCAuthenticator)
			var pathMatchers []*regexp.Regexp
			for _, pattern := range config.PathPatterns {
				matcher, err := regexp.Compile(pattern)
				if err != nil {
					if tt.expectError {
						// Expected error
						return
					}
					t.Errorf("Unexpected error compiling pattern %q: %v", pattern, err)
					return
				}
				pathMatchers = append(pathMatchers, matcher)
			}

			if tt.expectError {
				t.Error("Expected error but none occurred")
				return
			}

			// Verify the patterns match expectations
			if len(config.PathPatterns) != len(tt.expectPaths) {
				t.Errorf("Expected %d path patterns, got %d", len(tt.expectPaths), len(config.PathPatterns))
			}

			for i, expected := range tt.expectPaths {
				if i >= len(config.PathPatterns) {
					t.Errorf("Missing expected path pattern: %q", expected)
					continue
				}
				if config.PathPatterns[i] != expected {
					t.Errorf("Expected path pattern %q, got %q", expected, config.PathPatterns[i])
				}
			}
		})
	}
}

// Test the actual OIDC middleware directly - no mocking needed!
func TestOIDCMiddlewareActual(t *testing.T) {
	// Just test the middleware behavior directly by calling the authenticator's Middleware() method
	tests := []struct {
		name          string
		pathPatterns  []string
		requestPath   string
		expectSkipped bool
	}{
		{
			name:          "non_matching_path_skipped",
			pathPatterns:  []string{"/api/.*/query"},
			requestPath:   "/api/metrics/v1/receive",
			expectSkipped: true,
		},
		{
			name:          "matching_path_not_skipped", 
			pathPatterns:  []string{"/api/.*/query"},
			requestPath:   "/api/metrics/v1/query",
			expectSkipped: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create actual oidcAuthenticator with compiled path patterns
			authenticator := &oidcAuthenticator{
				tenant: "test-tenant",
				logger: log.NewNopLogger(), // Initialize logger to prevent panic
			}

			// Compile patterns exactly like the real newOIDCAuthenticator does
			for _, pattern := range tt.pathPatterns {
				matcher, err := regexp.Compile(pattern)
				if err != nil {
					t.Fatalf("Failed to compile pattern: %v", err)
				}
				authenticator.pathMatchers = append(authenticator.pathMatchers, matcher)
			}

			// Get the REAL middleware function
			middleware := authenticator.Middleware()

			handlerCalled := false
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", tt.requestPath, nil)
			rr := httptest.NewRecorder()

			// Test the real middleware
			middleware(testHandler).ServeHTTP(rr, req)

			if tt.expectSkipped {
				if !handlerCalled || rr.Code != http.StatusOK {
					t.Error("Path should be skipped and handler called")
				}
			} else {
				// Should attempt OIDC auth and fail (no token/invalid setup)
				if rr.Code == http.StatusOK {
					t.Error("Path should NOT be skipped - OIDC should run")
				}
			}
		})
	}
}

