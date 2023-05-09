package http

import (
	"fmt"
	"net/url"
	"sort"
	"testing"

	"github.com/efficientgo/core/testutil"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
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
		tc := tc
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

			testutil.Equals(t, m, mExp)
		})
	}
}

func TestEnforceValuesOnQuery(t *testing.T) {
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

			ou, err := url.Parse(fmt.Sprintf("/loki/api/v1/query_range?%s", tc.urlValues.Encode()))
			testutil.Ok(t, err)

			v, err := enforceValues(AuthzResponseData{Matchers: tc.accessMatchers}, ou)
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
