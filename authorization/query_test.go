package authorization

import (
	"reflect"
	"testing"
)

func Test_parseQueryNamespaces(t *testing.T) {
	tests := []struct {
		query   string
		want    []string
		wantErr bool
	}{
		{
			query:   `{kubernetes_namespace_name="test"}`,
			want:    []string{"test"},
			wantErr: false,
		},
		{
			query:   `{kubernetes_namespace_name="test",kubernetes_namespace_name="test2"}`,
			want:    []string{"test", "test2"},
			wantErr: false,
		},
		{
			query:   `{kubernetes_namespace_name=~"test|test2"}`,
			want:    []string{"test", "test2"},
			wantErr: false,
		},
		{
			query:   `{kubernetes_namespace_name=~"test|test2|test3.+"}`,
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got, err := parseQueryNamespaces(tt.query)
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
