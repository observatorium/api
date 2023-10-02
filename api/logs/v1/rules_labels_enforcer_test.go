package http

import (
	"net/url"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/prometheus/prometheus/model/labels"
)

func TestEnforceNamespaceLabels(t *testing.T) {
	tt := []struct {
		desc            string
		keys            []string
		accessMatchers  []*labels.Matcher
		namespaceLabels string
		expectedQuery   string
	}{
		{
			desc:            "empty_keys",
			namespaceLabels: "kubernetes_namespace_name=last-ns-name",
			expectedQuery:   "kubernetes_namespace_name=last-ns-name",
		},
		{
			desc:            "single_key_no_matcher",
			keys:            []string{"kubernetes_namespace_name"},
			namespaceLabels: "kubernetes_namespace_name=last-ns-name",
			expectedQuery:   "kubernetes_namespace_name=last-ns-name",
		},
		{
			desc: "single_key_wrong_matcher",
			keys: []string{"kubernetes_namespace_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_pod_name",
					Value: "pod-name-.*",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=last-ns-name",
			expectedQuery:   "kubernetes_namespace_name=last-ns-name",
		},
		{
			desc: "single_key_matching_matcher_wrong_value",
			keys: []string{"kubernetes_namespace_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "first-ns-name",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=last-ns-name",
			expectedQuery:   "kubernetes_namespace_name=last-ns-name",
		},
		{
			desc: "single_key_matching_matcher_matching_value_wrong_type",
			keys: []string{"kubernetes_namespace_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchNotEqual,
					Name:  "kubernetes_namespace_name",
					Value: "last-ns-name",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=last-ns-name",
			expectedQuery:   "kubernetes_namespace_name=last-ns-name",
		},
		{
			desc: "single_key_matching_matcher_matching_value",
			keys: []string{"kubernetes_namespace_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "last-ns-name",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=last-ns-name",
			expectedQuery:   "labels=kubernetes_namespace_name:last-ns-name",
		},
		{
			desc: "query with a single key with multiple occurences",
			keys: []string{"kubernetes_namespace_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name|another-ns-name",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=ns-name&kubernetes_namespace_name=another-ns-name",
			expectedQuery:   "labels=kubernetes_namespace_name:ns-name",
		},
		{
			desc: "query_with_multiple_keys_with_single_occurences",
			keys: []string{"kubernetes_namespace_name", "kubernetes_pod_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name",
				},
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_pod_name",
					Value: "my-pod",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=ns-name&kubernetes_pod_name=my-pod",
			expectedQuery:   "labels=kubernetes_namespace_name:ns-name,kubernetes_pod_name:my-pod",
		},
		{
			desc: "query_with_multiple_keys_with_single_occurences_but_only_one_matcher",
			keys: []string{"kubernetes_namespace_name", "kubernetes_pod_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=ns-name&kubernetes_pod_name=my-pod",
			expectedQuery:   "kubernetes_pod_name=my-pod&labels=kubernetes_namespace_name:ns-name",
		},
		{
			desc: "query_with_multiple_keys_with_multiple_occurences",
			keys: []string{"kubernetes_namespace_name", "kubernetes_pod_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name|ns-new-name",
				},
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_pod_name",
					Value: "my-pod|my-new-pod",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=ns-name&kubernetes_pod_name=my-pod&kubernetes_namespace_name=ns-new-name&kubernetes_pod_name=my-new-pod",
			expectedQuery:   "labels=kubernetes_namespace_name:ns-name,kubernetes_pod_name:my-pod",
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			matchers, err := initAuthzMatchers(tc.accessMatchers)
			testutil.Ok(t, err)

			queryValues, err := url.ParseQuery(tc.namespaceLabels)
			testutil.Ok(t, err)

			v := transformParametersInLabelFilter(tc.keys, matchers, queryValues)

			ac, err := url.QueryUnescape(v)
			testutil.Ok(t, err)
			testutil.Equals(t, tc.expectedQuery, ac)
		})
	}
}
