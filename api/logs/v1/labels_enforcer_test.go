package http

import (
	"net/url"
	"sort"
	"testing"

	"github.com/efficientgo/core/testutil"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

func TestEnforceValues(t *testing.T) {
	tt := []struct {
		desc           string
		accessMatchers []*labels.Matcher
		urlValues      url.Values
		expValues      url.Values
	}{
		{
			desc: "empty url values",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "log-test-0",
				},
			},
			urlValues: url.Values{},
			expValues: url.Values{},
		},
		{
			desc: "query with no matcher overlap",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name|another-ns-name|openshift-.*",
				},
			},
			urlValues: url.Values{
				"query": []string{"{kubernetes_container_name=\"logger\", kubernetes_pod_name=\"pod-name\"}"},
			},
			expValues: url.Values{
				"query": []string{"{kubernetes_namespace_name=~\"ns-name|another-ns-name|openshift-.*\", kubernetes_container_name=\"logger\", kubernetes_pod_name=\"pod-name\"}"},
			},
		},
		{
			desc: "query with accessible namespace",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name|another-ns-name|openshift-.*",
				},
			},
			urlValues: url.Values{
				"query": []string{"{kubernetes_namespace_name=\"ns-name\", kubernetes_container_name=\"logger\", kubernetes_pod_name=\"pod-name\"}"},
			},
			expValues: url.Values{
				"query": []string{"{kubernetes_namespace_name=\"ns-name\", kubernetes_container_name=\"logger\", kubernetes_pod_name=\"pod-name\"}"},
			},
		},
		{
			desc: "query with a forbidden namespace",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name|another-ns-name|openshift-.*",
				},
			},
			urlValues: url.Values{
				"query": []string{"{kubernetes_namespace_name=\"forbidden-ns|ns-name\", kubernetes_container_name=\"logger\", kubernetes_pod_name=\"pod-name\"}"},
			},
			expValues: url.Values{
				"query": []string{"{kubernetes_namespace_name=~\"ns-name|another-ns-name|openshift-.*\", kubernetes_container_name=\"logger\", kubernetes_pod_name=\"pod-name\"}"},
			},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			v, err := enforceValues(AuthzResponseData{Matchers: tc.accessMatchers}, tc.urlValues)
			testutil.Ok(t, err)

			if len(tc.urlValues.Encode()) == 0 {
				// Url values are empty, non need to do more checks.
				testutil.Equals(t, len(v), 0)
				return
			}

			u, err := url.ParseQuery(v)
			testutil.Ok(t, err)

			expr, err := logqlv2.ParseExpr(u.Get("query"))
			testutil.Ok(t, err)

			expected, err := logqlv2.ParseExpr(tc.expValues.Get("query"))
			testutil.Ok(t, err)

			smExpr, ok := expr.(*logqlv2.LogQueryExpr)
			testutil.Assert(t, ok)

			smExpected, ok := expected.(*logqlv2.LogQueryExpr)
			testutil.Assert(t, ok)

			m := smExpr.Matchers()
			mExp := smExpected.Matchers()

			sort.Slice(m, func(i, j int) bool {
				return m[i].Name < m[j].Name
			})

			sort.Slice(mExp, func(i, j int) bool {
				return mExp[i].Name < mExp[j].Name
			})

			testutil.Equals(t, m, mExp)
		})
	}
}

func TestEnforceNamespaceLabels(t *testing.T) {
	tt := []struct {
		desc            string
		accessMatchers  []*labels.Matcher
		namespaceLabels string
	}{
		{
			desc:            "empty access matchers values",
			accessMatchers:  []*labels.Matcher{},
			namespaceLabels: "",
		},
		{
			desc: "query with no namespace matcher",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_pod_name",
					Value: "pod-name-.*",
				},
			},
			namespaceLabels: "",
		},
		{
			desc: "query with no equals matchers",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchNotRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name",
				},
				{
					Type:  labels.MatchNotEqual,
					Name:  "kubernetes_namespace_name",
					Value: "another-ns-name",
				},
			},
			namespaceLabels: "",
		},
		{
			desc: "query with namespace matchers",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "ns-name",
				},
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "another-ns-name|last-ns-name",
				},
			},
			namespaceLabels: "labels=namespace:ns-name,namespace:another-ns-name,namespace:last-ns-name",
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			v := enforceNamespaceLabels(tc.accessMatchers, url.Values{})

			if len(tc.accessMatchers) == 0 {
				// No Access matchers, non need to do more checks.
				testutil.Equals(t, len(v), 0)
				return
			}

			ac, err := url.QueryUnescape(v)

			testutil.Ok(t, err)
			testutil.Equals(t, tc.namespaceLabels, ac)
		})
	}
}
