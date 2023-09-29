package http

// func TestEnforceNamespaceLabels(t *testing.T) {
// 	tt := []struct {
// 		desc            string
// 		accessMatchers  []*labels.Matcher
// 		namespaceLabels string
// 	}{
// 		{
// 			desc:            "empty access matchers values",
// 			accessMatchers:  []*labels.Matcher{},
// 			namespaceLabels: "",
// 		},
// 		{
// 			desc: "query with no namespace matcher",
// 			accessMatchers: []*labels.Matcher{
// 				{
// 					Type:  labels.MatchEqual,
// 					Name:  "kubernetes_pod_name",
// 					Value: "pod-name-.*",
// 				},
// 			},
// 			namespaceLabels: "",
// 		},
// 		{
// 			desc: "query with no equals matchers",
// 			accessMatchers: []*labels.Matcher{
// 				{
// 					Type:  labels.MatchNotRegexp,
// 					Name:  "kubernetes_namespace_name",
// 					Value: "ns-name",
// 				},
// 				{
// 					Type:  labels.MatchNotEqual,
// 					Name:  "kubernetes_namespace_name",
// 					Value: "another-ns-name",
// 				},
// 			},
// 			namespaceLabels: "",
// 		},
// 		{
// 			desc: "query with namespace matchers",
// 			accessMatchers: []*labels.Matcher{
// 				{
// 					Type:  labels.MatchEqual,
// 					Name:  "kubernetes_namespace_name",
// 					Value: "ns-name",
// 				},
// 				{
// 					Type:  labels.MatchRegexp,
// 					Name:  "kubernetes_namespace_name",
// 					Value: "another-ns-name|last-ns-name",
// 				},
// 			},
// 			namespaceLabels: "labels=kubernetes_namespace_name:ns-name,kubernetes_namespace_name:another-ns-name,kubernetes_namespace_name:last-ns-name",
// 		},
// 	}

// 	for _, tc := range tt {
// 		tc := tc
// 		t.Run(tc.desc, func(t *testing.T) {
// 			t.Parallel()

// 			v := enforceNamespaceLabels(tc.accessMatchers, url.Values{})

// 			if len(tc.accessMatchers) == 0 {
// 				// No Access matchers, non need to do more checks.
// 				testutil.Equals(t, len(v), 0)
// 				return
// 			}

// 			ac, err := url.QueryUnescape(v)

// 			testutil.Ok(t, err)
// 			testutil.Equals(t, tc.namespaceLabels, ac)
// 		})
// 	}
// }
