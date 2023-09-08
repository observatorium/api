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
		query   string
		want    []string
		wantErr bool
	}{
		{
			query:   `{namespace="test"}`,
			want:    []string{"test"},
			wantErr: false,
		},
		{
			query:   `{namespace="test",other_namespace_label="test2"}`,
			want:    []string{"test", "test2"},
			wantErr: false,
		},
		{
			query:   `{namespace="test",namespace="test2"}`,
			want:    []string{"test", "test2"},
			wantErr: false,
		},
		{
			query:   `{namespace=~"test|test2"}`,
			want:    []string{"test", "test2"},
			wantErr: false,
		},
		{
			query:   `{namespace=~"test|test2|test3.+"}`,
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got, err := parseQueryNamespaces(testNamespaceLabels, tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseQueryNamespaces() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseQueryNamespaces() got = %v, want %v", got, tt.want)
			}
		})
	}
}
