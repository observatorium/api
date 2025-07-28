package http

import (
	"fmt"
	"net/url"
	"sort"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/prometheus/prometheus/model/labels"

	logqlv2 "github.com/observatorium/api/logql/v2"
)

func TestEnforceValuesOnLabelValues(t *testing.T) {
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
			expValues: url.Values{
				"query": []string{`{kubernetes_namespace_name=~"log-test-0"}`},
			},
		},

		{
			desc: "user defined query",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "log-test-0",
				},
			},
			urlValues: url.Values{
				"query": []string{`{foo="bar"}`},
			},
			expValues: url.Values{
				"query": []string{`{foo="bar", kubernetes_namespace_name=~"log-test-0"}`},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			ou, err := url.Parse(fmt.Sprintf("/loki/api/v1/label/foo/values?%s", tc.urlValues.Encode()))
			testutil.Ok(t, err)

			v, err := enforceValues(AuthzResponseData{Matchers: tc.accessMatchers}, ou)
			testutil.Ok(t, err)

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

			testutil.Equals(t, matchersToStrings(mExp), matchersToStrings(m))
		})
	}
}

func TestEnforceValuesOnQuery(t *testing.T) {
	tt := []struct {
		desc           string
		accessMatchers []*labels.Matcher
		matcherOp      string
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
		{
			desc: "logical OR with query parameter",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-1|ns-2",
				},
			},
			matcherOp: logicalOr,
			urlValues: url.Values{
				"query": []string{`{app="test"}`},
			},
			expValues: url.Values{
				"query": []string{"{app=\"test\"} | kubernetes_namespace_name =~ \"ns-1|ns-2\""},
			},
		},
		{
			desc: "logical OR with multiple matchers",
			accessMatchers: []*labels.Matcher{
				{
					Type:  labels.MatchRegexp,
					Name:  "kubernetes_namespace_name",
					Value: "ns-1|ns-2",
				},
				{
					Type:  labels.MatchEqual,
					Name:  "cluster",
					Value: "prod",
				},
			},
			matcherOp: logicalOr,
			urlValues: url.Values{
				"query": []string{`{service="api"}`},
			},
			expValues: url.Values{
				"query": []string{"{service=\"api\"} | kubernetes_namespace_name =~ \"ns-1|ns-2\" or cluster = \"prod\""},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			ou, err := url.Parse(fmt.Sprintf("/loki/api/v1/query_range?%s", tc.urlValues.Encode()))
			testutil.Ok(t, err)

			authzData := AuthzResponseData{Matchers: tc.accessMatchers}
			if tc.matcherOp != "" {
				authzData.MatcherOp = tc.matcherOp
			}

			v, err := enforceValues(authzData, ou)
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

			testutil.Equals(t, matchersToStrings(mExp), matchersToStrings(m))

			if tc.matcherOp != "" {
				expQuery := tc.expValues.Get("query")
				actualQuery := smExpr.String()
				testutil.Equals(t, expQuery, actualQuery)
			}
		})
	}
}

func matchersToStrings(m []*labels.Matcher) []string {
	s := make([]string, len(m))
	for i, v := range m {
		s[i] = v.String()
	}
	return s
}
