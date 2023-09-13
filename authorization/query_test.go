package authorization

import (
	"reflect"
	"testing"
)

func Test_parseQuerySelectors(t *testing.T) {
	testSelectorLabels := map[string]bool{
		"namespace":             true,
		"other_namespace_label": true,
	}
	tests := []struct {
		query           string
		wantSelectors   map[string][]string
		wantHasWildcard bool
	}{
		{
			query: `{namespace="test"}`,
			wantSelectors: map[string][]string{
				"namespace": {"test"},
			},
		},
		{
			query: `{namespace="test",other_namespace_label="test2"}`,
			wantSelectors: map[string][]string{
				"namespace":             {"test"},
				"other_namespace_label": {"test2"},
			},
		},
		{
			query: `{namespace="test",namespace="test2"}`,
			wantSelectors: map[string][]string{
				"namespace": {"test", "test2"},
			},
		},
		{
			query: `{namespace=~"test|test2"}`,
			wantSelectors: map[string][]string{
				"namespace": {"test", "test2"},
			},
		},
		{
			query: `{namespace=~"test|test2|test3.+"}`,
			wantSelectors: map[string][]string{
				"namespace": {"test", "test2"},
			},
			wantHasWildcard: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			gotNamespaces, gotHasWildcard, err := parseLogStreamSelectors(testSelectorLabels, tt.query)
			if err != nil {
				t.Errorf("parseLogStreamSelectors() error = %v", err)
			}
			if !reflect.DeepEqual(gotNamespaces, tt.wantSelectors) {
				t.Errorf("parseLogStreamSelectors() got = %v, want %v", gotNamespaces, tt.wantSelectors)
			}
			if gotHasWildcard != tt.wantHasWildcard {
				t.Errorf("parseLogStreamSelectors() got = %v, want %v", gotHasWildcard, tt.wantHasWildcard)
			}
		})
	}
}
