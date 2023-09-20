package authorization

import "testing"

func TestIsMetaRequest(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "/loki/api/v1/labels",
			want: true,
		},
		{
			path: "/loki/api/v1/label/kubernetes_namespace_name/values",
			want: true,
		},
		{
			path: "/loki/api/v1/query_range",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isMetadataRequest(tt.path); got != tt.want {
				t.Errorf("isMetaRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
