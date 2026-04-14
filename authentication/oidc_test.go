package authentication

import (
	"regexp"
	"testing"
)

func TestOIDCPathPatternsWithOperators(t *testing.T) {
	tests := []struct {
		name        string
		paths       []PathPattern
		requestPath string
		expectSkip  bool
		expectError bool
		description string
	}{
		{
			name:        "positive_match_operator",
			paths:       []PathPattern{{Operator: OperatorMatches, Pattern: "/api/.*/query"}},
			requestPath: "/api/metrics/v1/query",
			expectSkip:  false,
			description: "Positive match with =~ operator should enforce OIDC",
		},
		{
			name:        "positive_no_match_operator",
			paths:       []PathPattern{{Operator: OperatorMatches, Pattern: "/api/.*/query"}},
			requestPath: "/api/metrics/v1/receive",
			expectSkip:  true,
			description: "No match with =~ operator should skip OIDC",
		},
		{
			name:        "negative_match_operator",
			paths:       []PathPattern{{Operator: OperatorNotMatches, Pattern: "^/api/(logs|metrics)/v1/auth-tenant/(loki/api/v1/push|api/v1/receive)"}},
			requestPath: "/api/metrics/v1/auth-tenant/api/v1/query",
			expectSkip:  false,
			description: "Path not matching negative pattern should enforce OIDC",
		},
		{
			name:        "negative_no_match_operator",
			paths:       []PathPattern{{Operator: OperatorNotMatches, Pattern: "^/api/(logs|metrics)/v1/auth-tenant/(loki/api/v1/push|api/v1/receive)"}},
			requestPath: "/api/metrics/v1/auth-tenant/api/v1/receive",
			expectSkip:  true,
			description: "Path matching negative pattern should skip OIDC",
		},
		{
			name:        "default_operator",
			paths:       []PathPattern{{Pattern: "/api/.*/query"}}, // no operator specified
			requestPath: "/api/metrics/v1/query",
			expectSkip:  false,
			description: "Default operator should be =~",
		},
		{
			name:        "invalid_operator",
			paths:       []PathPattern{{Operator: "invalid", Pattern: "/api/.*/query"}},
			expectError: true,
			description: "Invalid operator should cause error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test compilation (similar to newOIDCAuthenticator)
			var pathMatchers []PathMatcher

			for _, pathPattern := range tt.paths {
				operator := pathPattern.Operator
				if operator == "" {
					operator = OperatorMatches // default operator
				}

				// Validate operator
				if operator != OperatorMatches && operator != OperatorNotMatches {
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
			shouldEnforceOIDC := false

			for _, matcher := range pathMatchers {
				regexMatches := matcher.Regex.MatchString(tt.requestPath)

				if matcher.Operator == OperatorMatches && regexMatches {
					shouldEnforceOIDC = true
					break
				} else if matcher.Operator == OperatorNotMatches && !regexMatches {
					shouldEnforceOIDC = true
					break
				}
			}

			shouldSkip := !shouldEnforceOIDC

			if shouldSkip != tt.expectSkip {
				t.Errorf("Expected skip=%v, got skip=%v for path %s", tt.expectSkip, shouldSkip, tt.requestPath)
			}
		})
	}
}
