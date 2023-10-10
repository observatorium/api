package authorization

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/efficientgo/core/testutil"
)

func Test_parseQueryParametersSelectors(t *testing.T) {
	testSelectorLabels := map[string]bool{
		"namespace":             true,
		"other_namespace_label": true,
	}
	tests := []struct {
		queryParameters string
		wantSelectors   map[string][]string
	}{
		{
			queryParameters: `namespace=test`,
			wantSelectors: map[string][]string{
				"namespace": {"test"},
			},
		},
		{
			queryParameters: `namespace=test&other_namespace_label=test2`,
			wantSelectors: map[string][]string{
				"namespace":             {"test"},
				"other_namespace_label": {"test2"},
			},
		},
		{
			queryParameters: `namespace=test&namespace=test2`,
			wantSelectors: map[string][]string{
				"namespace": {"test", "test2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.queryParameters, func(t *testing.T) {
			queryValues, err := url.ParseQuery(tt.queryParameters)
			testutil.Ok(t, err)

			gotNamespaces, _, err := parseLogRulesSelectors(testSelectorLabels, queryValues)
			if err != nil {
				t.Errorf("parseLogStreamSelectors() error = %v", err)
			}
			if !reflect.DeepEqual(gotNamespaces, tt.wantSelectors) {
				t.Errorf("parseLogStreamSelectors() got = %v, want %v", gotNamespaces, tt.wantSelectors)
			}
		})
	}
}
