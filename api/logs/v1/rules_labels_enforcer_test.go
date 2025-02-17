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
		labels          []string
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
			labels:          []string{"kubernetes_namespace_name"},
			namespaceLabels: "kubernetes_namespace_name=last-ns-name",
			expectedQuery:   "kubernetes_namespace_name=last-ns-name",
		},
		{
			desc:   "single_key_wrong_matcher",
			labels: []string{"kubernetes_namespace_name"},
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
			desc:   "single_key_matching_matcher_wrong_value",
			labels: []string{"kubernetes_namespace_name"},
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
			desc:   "single_key_matching_matcher_matching_value_wrong_type",
			labels: []string{"kubernetes_namespace_name"},
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
			desc:   "single_key_matching_matcher_matching_value",
			labels: []string{"kubernetes_namespace_name"},
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
			desc:   "query with a single key with multiple occurrences",
			labels: []string{"kubernetes_namespace_name"},
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
			desc:   "query_with_multiple_keys_with_single_occurrences",
			labels: []string{"kubernetes_namespace_name", "kubernetes_pod_name"},
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
			desc:   "query_with_multiple_keys_with_single_occurrences_but_only_one_matcher",
			labels: []string{"kubernetes_namespace_name", "kubernetes_pod_name"},
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
			desc:   "query_with_multiple_keys_with_multiple_occurrences",
			labels: []string{"kubernetes_namespace_name", "kubernetes_pod_name"},
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
		{
			desc:   "query_with_multiple_keys_with_single_occurrences_but_multiple_matchers",
			labels: []string{"kubernetes_namespace_name", "k8s_namespace_name"},
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name|ns-new-name",
				},
				{
					Type:  labels.MatchRegexp,
					Name:  "k8s_namespace_name",
					Value: "ns-name|ns-new-name",
				},
			},
			namespaceLabels: "kubernetes_namespace_name=ns-name",
			expectedQuery:   "labels=kubernetes_namespace_name:ns-name",
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			matchers, err := initAuthzMatchers(tc.accessMatchers)
			testutil.Ok(t, err)

			queryValues, err := url.ParseQuery(tc.namespaceLabels)
			testutil.Ok(t, err)

			v := transformParametersInLabelFilter(tc.labels, matchers, queryValues)

			ac, err := url.QueryUnescape(v)
			testutil.Ok(t, err)
			testutil.Equals(t, tc.expectedQuery, ac)
		})
	}
}

func TestLabelsInQueryParams(t *testing.T) {
	tt := []struct {
		desc          string
		labels        []string
		matchers      []*labels.Matcher
		queryParams   string
		expectedError bool
	}{
		{
			desc:          "no_labels",
			queryParams:   "kubernetes_namespace_name=last-ns-name",
			expectedError: false,
		},
		{
			desc:          "single_label_no_matcher",
			labels:        []string{"kubernetes_namespace_name"},
			queryParams:   "kubernetes_namespace_name=last-ns-name",
			expectedError: true,
		},
		{
			desc:   "single_label_wrong_matcher",
			labels: []string{"kubernetes_namespace_name"},
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_pod_name",
					Value: "pod-name-.*",
				},
			},
			queryParams:   "kubernetes_namespace_name=last-ns-name",
			expectedError: true,
		},
		{
			desc:   "single_label_matching_matcher_wrong_value",
			labels: []string{"kubernetes_namespace_name"},
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "first-ns-name",
				},
			},
			queryParams:   "kubernetes_namespace_name=last-ns-name",
			expectedError: true,
		},
		{
			desc:   "single_label_matching_matcher_matching_value",
			labels: []string{"kubernetes_namespace_name"},
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "last-ns-name",
				},
			},
			queryParams:   "kubernetes_namespace_name=last-ns-name",
			expectedError: false,
		},
		{
			desc:   "multiple_labels_with_single_occurrences",
			labels: []string{"kubernetes_namespace_name", "kubernetes_pod_name"},
			matchers: []*labels.Matcher{
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
			queryParams:   "kubernetes_namespace_name=ns-name&kubernetes_pod_name=my-pod",
			expectedError: false,
		},
		{
			desc:   "only_the_legacy_namespace_label",
			labels: []string{"kubernetes_namespace_name", "k8s_namespace_name"},
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name",
				},
				{
					Type:  labels.MatchEqual,
					Name:  "k8s_namespace_name",
					Value: "ns-name",
				},
			},
			queryParams:   "kubernetes_namespace_name=ns-name",
			expectedError: false,
		},
		{
			desc:   "only_the_new_namespace_label",
			labels: []string{"kubernetes_namespace_name", "k8s_namespace_name"},
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name",
				},
				{
					Type:  labels.MatchEqual,
					Name:  "k8s_namespace_name",
					Value: "ns-name",
				},
			},
			queryParams:   "k8s_namespace_name=ns-name",
			expectedError: false,
		},
		{
			desc:   "both_namespace_labels_are_invalid",
			labels: []string{"kubernetes_namespace_name", "k8s_namespace_name"},
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name",
				},
				{
					Type:  labels.MatchEqual,
					Name:  "k8s_namespace_name",
					Value: "ns-name",
				},
			},
			queryParams:   "kubernetes_namespace_name=ns-name&k8s_namespace_name=ns-name",
			expectedError: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			queryValues, err := url.ParseQuery(tc.queryParams)
			testutil.Ok(t, err)

			_, err = validateQueryParams(queryValues, tc.labels, tc.matchers)
			if tc.expectedError {
				testutil.NotOk(t, err)
			} else {
				testutil.Ok(t, err)
			}
		})
	}
}
