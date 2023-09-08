package authorization

import (
	"reflect"
	"testing"
)

func Test_parseQueryNamespaces(t *testing.T) {
	testNamespaceLabels := map[string]bool{
		"namespace":             true,
		"other_namespace_label": true,
	}
	tests := []struct {
		query           string
		wantNamespaces  []string
		wantHasWildcard bool
	}{
		{
			query:          `{namespace="test"}`,
			wantNamespaces: []string{"test"},
		},
		{
			query:          `{namespace="test",other_namespace_label="test2"}`,
			wantNamespaces: []string{"test", "test2"},
		},
		{
			query:          `{namespace="test",namespace="test2"}`,
			wantNamespaces: []string{"test", "test2"},
		},
		{
			query:          `{namespace=~"test|test2"}`,
			wantNamespaces: []string{"test", "test2"},
		},
		{
			query:           `{namespace=~"test|test2|test3.+"}`,
			wantNamespaces:  []string{"test", "test2"},
			wantHasWildcard: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			gotNamespaces, gotHasWildcard, err := parseQueryNamespaces(testNamespaceLabels, tt.query)
			if err != nil {
				t.Errorf("parseQueryNamespaces() error = %v", err)
			}
			if !reflect.DeepEqual(gotNamespaces, tt.wantNamespaces) {
				t.Errorf("parseQueryNamespaces() got = %v, want %v", gotNamespaces, tt.wantNamespaces)
			}
			if gotHasWildcard != tt.wantHasWildcard {
				t.Errorf("parseQueryNamespaces() got = %v, want %v", gotHasWildcard, tt.wantHasWildcard)
			}
		})
	}
}
