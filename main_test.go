package main

import (
	"regexp"
	"testing"

	"github.com/ghodss/yaml"
)

func TestTenantConfigurationPathPatterns(t *testing.T) {
	tests := []struct {
		name           string
		yamlConfig     string
		expectError    bool
		expectedTenant *tenant
		description    string
	}{
		{
			name: "valid_mixed_auth_config",
			yamlConfig: `
tenants:
  - name: "test-tenant"
    id: "tenant-123"
    oidc:
      paths:
        - operator: "=~"
          pattern: "/api/.*/query"
        - operator: "=~"
          pattern: "/api/.*/series"
      clientID: "test-client-id"
      issuerURL: "https://auth.example.com"
    mTLS:
      paths:
        - operator: "=~"
          pattern: "/api/.*/receive"
        - operator: "=~"
          pattern: "/api/.*/rules"
      ca: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"
`,
			expectError: false,
			description: "Valid configuration with both OIDC and mTLS path patterns",
		},
		{
			name: "oidc_only_config",
			yamlConfig: `
tenants:
  - name: "oidc-tenant"
    id: "tenant-456"
    oidc:
      paths:
        - operator: "=~"
          pattern: "/api/.*"
      clientID: "oidc-client-id"
      issuerURL: "https://oidc.example.com"
`,
			expectError: false,
			description: "Valid configuration with only OIDC authentication",
		},
		{
			name: "mtls_only_config",
			yamlConfig: `
tenants:
  - name: "mtls-tenant"
    id: "tenant-789"
    mTLS:
      paths:
        - operator: "=~"
          pattern: "/api/.*"
      ca: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"
`,
			expectError: false,
			description: "Valid configuration with only mTLS authentication",
		},
		{
			name: "empty_paths_config",
			yamlConfig: `
tenants:
  - name: "empty-paths-tenant"
    id: "tenant-empty"
    oidc:
      paths: []
      clientID: "test-client-id"
      issuerURL: "https://auth.example.com"
`,
			expectError: false,
			description: "Valid configuration with empty paths (should apply to all paths)",
		},
		{
			name: "complex_regex_patterns",
			yamlConfig: `
tenants:
  - name: "regex-tenant"
    id: "tenant-regex"
    oidc:
      paths:
        - operator: "=~"
          pattern: "^/api/metrics/.*/(query|query_range|series|labels)$"
      clientID: "test-client-id"
      issuerURL: "https://auth.example.com"
    mTLS:
      paths:
        - operator: "=~"
          pattern: "^/api/metrics/.*/(receive|rules)$"
        - operator: "=~"
          pattern: "^/api/logs/.*/rules$"
      ca: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"
`,
			expectError: false,
			description: "Valid configuration with complex regex patterns",
		},
		{
			name: "invalid_regex_pattern",
			yamlConfig: `
tenants:
  - name: "invalid-regex-tenant"
    id: "tenant-invalid"
    oidc:
      paths:
        - operator: "=~"
          pattern: "[invalid-regex"
      clientID: "test-client-id"
      issuerURL: "https://auth.example.com"
`,
			expectError: true,
			description: "Configuration with invalid regex pattern should fail",
		},
		{
			name: "overlapping_patterns",
			yamlConfig: `
tenants:
  - name: "overlap-tenant"
    id: "tenant-overlap"
    oidc:
      paths:
        - operator: "=~"
          pattern: "/api/.*"
      clientID: "test-client-id"
      issuerURL: "https://auth.example.com"
    mTLS:
      paths:
        - operator: "=~"
          pattern: "/api/.*/receive"
      ca: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"
`,
			expectError: false,
			description: "Configuration with overlapping patterns (both auth methods could apply)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse YAML config
			var tenantsCfg struct {
				Tenants []*tenant `json:"tenants"`
			}

			err := yaml.Unmarshal([]byte(tt.yamlConfig), &tenantsCfg)
			if err != nil {
				t.Fatalf("Failed to unmarshal YAML config: %v", err)
			}

			if len(tenantsCfg.Tenants) == 0 {
				t.Fatal("No tenants found in config")
			}

			tenant := tenantsCfg.Tenants[0]

			// Test OIDC path pattern compilation
			if tenant.OIDC != nil {
				for _, pathPattern := range tenant.OIDC.Paths {
					matcher, err := regexp.Compile(pathPattern.Pattern)
					if tt.expectError {
						if err == nil {
							t.Errorf("Expected error for invalid regex pattern %q, but got none", pathPattern.Pattern)
						}
						return
					}
					if err != nil {
						t.Errorf("Failed to compile OIDC pattern %q: %v", pathPattern.Pattern, err)
						return
					}
					// Path pattern compilation is now handled by the authenticator during initialization
					_ = matcher // Just verify it compiles
				}
			}

			// Test mTLS path pattern compilation
			if tenant.MTLS != nil {
				for _, pathPattern := range tenant.MTLS.Paths {
					matcher, err := regexp.Compile(pathPattern.Pattern)
					if tt.expectError {
						if err == nil {
							t.Errorf("Expected error for invalid regex pattern %q, but got none", pathPattern.Pattern)
						}
						return
					}
					if err != nil {
						t.Errorf("Failed to compile mTLS pattern %q: %v", pathPattern.Pattern, err)
						return
					}
					// Path pattern compilation is now handled by the authenticator during initialization
					_ = matcher // Just verify it compiles
				}
			}

			// If we got here and expected an error, the test failed
			if tt.expectError {
				t.Error("Expected error but none occurred")
			}

			// Validate tenant structure
			if tenant.Name == "" {
				t.Error("Tenant name should not be empty")
			}
			if tenant.ID == "" {
				t.Error("Tenant ID should not be empty")
			}
		})
	}
}

func TestPathMatchingBehavior(t *testing.T) {
	tests := []struct {
		name         string
		oidcPaths    []string
		mtlsPaths    []string
		testPath     string
		expectOIDC   bool
		expectMTLS   bool
		description  string
	}{
		{
			name:        "read_path_oidc_only",
			oidcPaths:   []string{"/api/.*/query", "/api/.*/series"},
			mtlsPaths:   []string{"/api/.*/receive", "/api/.*/rules"},
			testPath:    "/api/metrics/v1/query",
			expectOIDC:  true,
			expectMTLS:  false,
			description: "Read path should match OIDC but not mTLS",
		},
		{
			name:        "write_path_mtls_only",
			oidcPaths:   []string{"/api/.*/query", "/api/.*/series"},
			mtlsPaths:   []string{"/api/.*/receive", "/api/.*/rules"},
			testPath:    "/api/metrics/v1/receive",
			expectOIDC:  false,
			expectMTLS:  true,
			description: "Write path should match mTLS but not OIDC",
		},
		{
			name:        "overlapping_path_both_match",
			oidcPaths:   []string{"/api/.*"},
			mtlsPaths:   []string{"/api/.*/receive"},
			testPath:    "/api/metrics/v1/receive",
			expectOIDC:  true,
			expectMTLS:  true,
			description: "Overlapping patterns should both match",
		},
		{
			name:        "no_match_either",
			oidcPaths:   []string{"/api/.*/query"},
			mtlsPaths:   []string{"/api/.*/receive"},
			testPath:    "/health",
			expectOIDC:  false,
			expectMTLS:  false,
			description: "Unmatched path should not trigger either auth method",
		},
		{
			name:        "complex_regex_matching",
			oidcPaths:   []string{"^/api/metrics/.*/(query|series|labels)$"},
			mtlsPaths:   []string{"^/api/.*/receive$"},
			testPath:    "/api/metrics/v1/labels",
			expectOIDC:  true,
			expectMTLS:  false,
			description: "Complex regex should match correctly",
		},
		{
			name:        "case_sensitive_matching",
			oidcPaths:   []string{"/api/.*/Query"},  // uppercase Q
			mtlsPaths:   []string{"/api/.*/receive"},
			testPath:    "/api/metrics/v1/query",    // lowercase q
			expectOIDC:  false,
			expectMTLS:  false,
			description: "Pattern matching should be case sensitive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile OIDC patterns
			var oidcMatchers []*regexp.Regexp
			for _, pattern := range tt.oidcPaths {
				matcher, err := regexp.Compile(pattern)
				if err != nil {
					t.Fatalf("Failed to compile OIDC pattern %q: %v", pattern, err)
				}
				oidcMatchers = append(oidcMatchers, matcher)
			}

			// Compile mTLS patterns
			var mtlsMatchers []*regexp.Regexp
			for _, pattern := range tt.mtlsPaths {
				matcher, err := regexp.Compile(pattern)
				if err != nil {
					t.Fatalf("Failed to compile mTLS pattern %q: %v", pattern, err)
				}
				mtlsMatchers = append(mtlsMatchers, matcher)
			}

			// Test OIDC matching
			oidcMatches := false
			for _, matcher := range oidcMatchers {
				if matcher.MatchString(tt.testPath) {
					oidcMatches = true
					break
				}
			}

			// Test mTLS matching
			mtlsMatches := false
			for _, matcher := range mtlsMatchers {
				if matcher.MatchString(tt.testPath) {
					mtlsMatches = true
					break
				}
			}

			// Verify results
			if oidcMatches != tt.expectOIDC {
				t.Errorf("OIDC matching: expected %v, got %v for path %q", tt.expectOIDC, oidcMatches, tt.testPath)
			}

			if mtlsMatches != tt.expectMTLS {
				t.Errorf("mTLS matching: expected %v, got %v for path %q", tt.expectMTLS, mtlsMatches, tt.testPath)
			}
		})
	}
}


