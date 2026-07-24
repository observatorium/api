package v1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/grafana/tempo/pkg/tempopb"
	commonv1 "github.com/grafana/tempo/pkg/tempopb/common/v1"
	resourcev1 "github.com/grafana/tempo/pkg/tempopb/resource/v1"
	tracev1 "github.com/grafana/tempo/pkg/tempopb/trace/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apilogsv1 "github.com/observatorium/api/api/logs/v1"
	"github.com/observatorium/api/authorization"
)

func TestForbidOtherAPIs(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := WithTraceQLNamespaceSelectAndForbidOtherAPIs(true)(nextHandler)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"trace by ID", "/tempo/api/traces/abc123", http.StatusOK},
		{"search", "/tempo/api/search", http.StatusOK},
		{"search tags blocked", "/tempo/api/search/tags", http.StatusForbidden},
		{"search tag values blocked", "/tempo/api/search/tag/name/values", http.StatusForbidden},
		{"v2 search tags blocked", "/tempo/api/v2/search/tags", http.StatusForbidden},
		{"v2 search tag values for service.name", "/tempo/api/v2/search/tag/resource.service.name/values", http.StatusOK},
		{"v2 search tag values for k8s.namespace.name", "/tempo/api/v2/search/tag/resource.k8s.namespace.name/values", http.StatusOK},
		{"v2 search tag values for other resource attributes blocked", "/tempo/api/v2/search/tag/resource.other/values", http.StatusForbidden},
		{"v2 search tag values for span attribtues blocked", "/tempo/api/v2/search/tag/span.http.method/values", http.StatusForbidden},
		{"metrics blocked", "/tempo/api/metrics/query_range", http.StatusForbidden},
		{"echo blocked", "/tempo/api/echo", http.StatusForbidden},
		{"overrides blocked", "/tempo/api/overrides", http.StatusForbidden},
		{"v2 trace by ID", "/tempo/api/v2/traces/abc123", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestCleanTrace(t *testing.T) {
	tests := []struct {
		name              string
		allowedNamespaces map[string]bool
		trace             *tempopb.Trace
		expected          *tempopb.Trace
	}{
		{
			name: "not allowed namespace",
			allowedNamespaces: map[string]bool{
				"allowed-ns": true,
			},
			trace: &tempopb.Trace{
				ResourceSpans: []*tracev1.ResourceSpans{
					{
						Resource: &resourcev1.Resource{
							Attributes: []*commonv1.KeyValue{
								createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
								createStringAttribute("service.name", "frontend"),
								createStringAttribute("resource1", "val"),
							},
						},
						ScopeSpans: []*tracev1.ScopeSpans{
							{
								Scope: &commonv1.InstrumentationScope{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("scope1", "val"),
									},
								},
								Spans: []*tracev1.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("span1", "val"),
										},
										Events: []*tracev1.Span_Event{
											{
												Name: "event",
												Attributes: []*commonv1.KeyValue{
													createStringAttribute("event1", "val"),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: &tempopb.Trace{
				ResourceSpans: []*tracev1.ResourceSpans{
					{
						Resource: &resourcev1.Resource{
							Attributes: []*commonv1.KeyValue{
								createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
								createStringAttribute("service.name", "frontend"),
							},
						},
						ScopeSpans: []*tracev1.ScopeSpans{
							{
								Scope: &commonv1.InstrumentationScope{
									Attributes: []*commonv1.KeyValue{},
								},
								Spans: []*tracev1.Span{
									{
										Attributes: []*commonv1.KeyValue{},
										Events:     []*tracev1.Span_Event{},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "allowed namespace",
			allowedNamespaces: map[string]bool{
				"allowed-ns": true,
			},
			trace: &tempopb.Trace{
				ResourceSpans: []*tracev1.ResourceSpans{
					{
						Resource: &resourcev1.Resource{
							Attributes: []*commonv1.KeyValue{
								createStringAttribute("k8s.namespace.name", "allowed-ns"),
								createStringAttribute("service.name", "frontend2"),
								createStringAttribute("resource1", "val"),
							},
						},
						ScopeSpans: []*tracev1.ScopeSpans{
							{
								Scope: &commonv1.InstrumentationScope{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("scope1", "val"),
									},
								},
								Spans: []*tracev1.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("span1", "val"),
										},
										Events: []*tracev1.Span_Event{
											{
												Name: "event",
												Attributes: []*commonv1.KeyValue{
													createStringAttribute("event1", "val"),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: &tempopb.Trace{
				ResourceSpans: []*tracev1.ResourceSpans{
					{
						Resource: &resourcev1.Resource{
							Attributes: []*commonv1.KeyValue{
								createStringAttribute("k8s.namespace.name", "allowed-ns"),
								createStringAttribute("service.name", "frontend2"),
								createStringAttribute("resource1", "val"),
							},
						},
						ScopeSpans: []*tracev1.ScopeSpans{
							{
								Scope: &commonv1.InstrumentationScope{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("scope1", "val"),
									},
								},
								Spans: []*tracev1.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("span1", "val"),
										},
										Events: []*tracev1.Span_Event{
											{
												Name: "event",
												Attributes: []*commonv1.KeyValue{
													createStringAttribute("event1", "val"),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "missing namespace attribute",
			allowedNamespaces: map[string]bool{
				"allowed-ns": true,
			},
			trace: &tempopb.Trace{
				ResourceSpans: []*tracev1.ResourceSpans{
					{
						Resource: &resourcev1.Resource{
							Attributes: []*commonv1.KeyValue{
								createStringAttribute("service.name", "backend"),
								createStringAttribute("resource1", "val"),
							},
						},
						ScopeSpans: []*tracev1.ScopeSpans{
							{
								Scope: &commonv1.InstrumentationScope{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("scope1", "val"),
									},
								},
								Spans: []*tracev1.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("span1", "val"),
										},
										Events: []*tracev1.Span_Event{
											{
												Name: "event",
												Attributes: []*commonv1.KeyValue{
													createStringAttribute("event1", "val"),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: &tempopb.Trace{
				ResourceSpans: []*tracev1.ResourceSpans{
					{
						Resource: &resourcev1.Resource{
							Attributes: []*commonv1.KeyValue{
								createStringAttribute("service.name", "backend"),
							},
						},
						ScopeSpans: []*tracev1.ScopeSpans{
							{
								Scope: &commonv1.InstrumentationScope{
									Attributes: []*commonv1.KeyValue{},
								},
								Spans: []*tracev1.Span{
									{
										Attributes: []*commonv1.KeyValue{},
										Events:     []*tracev1.Span_Event{},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, traceRBAC(test.allowedNamespaces, test.trace))
		})
	}
}

func createStringAttribute(key, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{
		Key:   key,
		Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}},
	}
}

func TestRBACSearchResult(t *testing.T) {
	tests := []struct {
		name              string
		allowedNamespaces map[string]bool
		searchResponse    *tempopb.SearchResponse
		expected          *tempopb.SearchResponse
	}{
		{
			name:              "not allowed namespace",
			allowedNamespaces: map[string]bool{"allowed-ns": true},
			searchResponse: &tempopb.SearchResponse{
				Traces: []*tempopb.TraceSearchMetadata{
					{
						SpanSet: &tempopb.SpanSet{
							Spans: []*tempopb.Span{
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
										createStringAttribute("span1", "val"),
									},
								},
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
										createStringAttribute("span2", "val"),
									},
								},
							},
						},
						SpanSets: []*tempopb.SpanSet{
							{
								Spans: []*tempopb.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
											createStringAttribute("span1", "val"),
										},
									},
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
											createStringAttribute("span2", "val"),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: &tempopb.SearchResponse{
				Traces: []*tempopb.TraceSearchMetadata{
					{
						SpanSet: &tempopb.SpanSet{
							Spans: []*tempopb.Span{
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
									},
								},
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
									},
								},
							},
						},
						SpanSets: []*tempopb.SpanSet{
							{
								Spans: []*tempopb.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
										},
									},
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "not-allowed-namespace"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:              "allowed namespace",
			allowedNamespaces: map[string]bool{"allowed-ns": true},
			searchResponse: &tempopb.SearchResponse{
				Traces: []*tempopb.TraceSearchMetadata{
					{
						SpanSet: &tempopb.SpanSet{
							Spans: []*tempopb.Span{
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "allowed-ns"),
										createStringAttribute("span1", "val"),
									},
								},
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "allowed-ns"),
										createStringAttribute("span2", "val"),
									},
								},
							},
						},
						SpanSets: []*tempopb.SpanSet{
							{
								Spans: []*tempopb.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "allowed-ns"),
											createStringAttribute("span1", "val"),
										},
									},
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "allowed-ns"),
											createStringAttribute("span2", "val"),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: &tempopb.SearchResponse{
				Traces: []*tempopb.TraceSearchMetadata{
					{
						SpanSet: &tempopb.SpanSet{
							Spans: []*tempopb.Span{
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "allowed-ns"),
										createStringAttribute("span1", "val"),
									},
								},
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("k8s.namespace.name", "allowed-ns"),
										createStringAttribute("span2", "val"),
									},
								},
							},
						},
						SpanSets: []*tempopb.SpanSet{
							{
								Spans: []*tempopb.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "allowed-ns"),
											createStringAttribute("span1", "val"),
										},
									},
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("k8s.namespace.name", "allowed-ns"),
											createStringAttribute("span2", "val"),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:              "missing namespace",
			allowedNamespaces: map[string]bool{"allowed-ns": true},
			searchResponse: &tempopb.SearchResponse{
				Traces: []*tempopb.TraceSearchMetadata{
					{
						SpanSet: &tempopb.SpanSet{
							Spans: []*tempopb.Span{
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("foo", "bar"),
										createStringAttribute("span1", "val"),
									},
								},
								{
									Attributes: []*commonv1.KeyValue{
										createStringAttribute("span2", "val"),
									},
								},
							},
						},
						SpanSets: []*tempopb.SpanSet{
							{
								Spans: []*tempopb.Span{
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("foo", "bar"),
											createStringAttribute("span1", "val"),
										},
									},
									{
										Attributes: []*commonv1.KeyValue{
											createStringAttribute("span2", "val"),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: &tempopb.SearchResponse{
				Traces: []*tempopb.TraceSearchMetadata{
					{
						SpanSet: &tempopb.SpanSet{
							Spans: []*tempopb.Span{
								{
									Attributes: []*commonv1.KeyValue{},
								},
								{
									Attributes: []*commonv1.KeyValue{},
								},
							},
						},
						SpanSets: []*tempopb.SpanSet{
							{
								Spans: []*tempopb.Span{
									{
										Attributes: []*commonv1.KeyValue{},
									},
									{
										Attributes: []*commonv1.KeyValue{},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, searchResponseRBAC(test.allowedNamespaces, test.searchResponse))
		})
	}
}

func contextWithAllowedNamespaces(t *testing.T, namespaces []string) context.Context {
	t.Helper()
	data := fmt.Sprintf(`{"matchers":[{"name":"namespace","value":"%s","type":1}]}`, url.QueryEscape(strings.Join(namespaces, "|")))

	var captured context.Context
	handler := apilogsv1.WithEnforceAuthorizationLabels()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Context()
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authorization.WithData(req.Context(), data))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, captured)
	return captured
}

func makeResponse(ctx context.Context, statusCode int, path string, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    (&http.Request{URL: &url.URL{Path: path}}).WithContext(ctx),
	}
}

func TestResponseRBACModifier(t *testing.T) {
	modifier := responseRBACModifier(log.NewNopLogger())
	ctx := contextWithAllowedNamespaces(t, []string{"allowed-ns"})

	t.Run("v1 trace endpoint", func(t *testing.T) {
		resp := makeResponse(ctx, http.StatusOK, "/api/traces/abc123", `{
  "batches": [
    {
      "resource": {
        "attributes": [
          {"key": "k8s.namespace.name", "value": {"stringValue": "allowed-ns"}}
        ]
      },
      "scopeSpans": [
        {"scope": {}, "spans": [
          {"attributes": [{"key": "span1", "value": {"stringValue": "val"}}]}
        ]}
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key": "k8s.namespace.name", "value": {"stringValue": "blocked-ns"}},
          {"key": "service.name", "value": {"stringValue": "blocked-svc"}}
        ]
      },
      "scopeSpans": [
        {"scope": {}, "spans": [
          {"attributes": [{"key": "span2", "value": {"stringValue": "val"}}]}
        ]}
      ]
    }
  ]
}`, nil)

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.JSONEq(t, `{
  "batches": [
    {
      "resource": {
        "attributes": [
          {"key": "k8s.namespace.name", "value": {"stringValue": "allowed-ns"}}
        ]
      },
      "scopeSpans": [
        {"scope": {}, "spans": [
          {"attributes": [{"key": "span1", "value": {"stringValue": "val"}}]}
        ]}
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key": "k8s.namespace.name", "value": {"stringValue": "blocked-ns"}},
          {"key": "service.name", "value": {"stringValue": "blocked-svc"}}
        ]
      },
      "scopeSpans": [
        {"scope": {"attributes": []}, "spans": [
          {"attributes": [], "events": []}
        ]}
      ]
    }
  ]
}`, string(body))
	})

	t.Run("v2 trace endpoint", func(t *testing.T) {
		resp := makeResponse(ctx, http.StatusOK, "/api/v2/traces/abc123", `{
  "trace": {
    "resourceSpans": [
      {
        "resource": {
          "attributes": [
            {"key": "k8s.namespace.name", "value": {"stringValue": "allowed-ns"}}
          ]
        },
        "scopeSpans": [
          {"scope": {}, "spans": [
            {"attributes": [{"key": "span1", "value": {"stringValue": "val"}}]}
          ]}
        ]
      },
      {
        "resource": {
          "attributes": [
            {"key": "k8s.namespace.name", "value": {"stringValue": "blocked-ns"}},
            {"key": "service.name", "value": {"stringValue": "blocked-svc"}}
          ]
        },
        "scopeSpans": [
          {"scope": {}, "spans": [
            {"attributes": [{"key": "span2", "value": {"stringValue": "val"}}]}
          ]}
        ]
      }
    ]
  }
}`, nil)

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.JSONEq(t, `{
  "trace": {
    "resourceSpans": [
      {
        "resource": {
          "attributes": [
            {"key": "k8s.namespace.name", "value": {"stringValue": "allowed-ns"}}
          ]
        },
        "scopeSpans": [
          {"scope": {}, "spans": [
            {"attributes": [{"key": "span1", "value": {"stringValue": "val"}}]}
          ]}
        ]
      },
      {
        "resource": {
          "attributes": [
            {"key": "k8s.namespace.name", "value": {"stringValue": "blocked-ns"}},
            {"key": "service.name", "value": {"stringValue": "blocked-svc"}}
          ]
        },
        "scopeSpans": [
          {"scope": {}, "spans": [{}]}
        ]
      }
    ]
  }
}`, string(body))
	})

	t.Run("search endpoint", func(t *testing.T) {
		resp := makeResponse(ctx, http.StatusOK, "/api/search", `{
  "traces": [
    {
      "spanSets": [
        {
          "spans": [
            {"attributes": [
              {"key": "k8s.namespace.name", "value": {"stringValue": "allowed-ns"}},
              {"key": "extra", "value": {"stringValue": "val"}}
            ]},
            {"attributes": [
              {"key": "k8s.namespace.name", "value": {"stringValue": "blocked-ns"}},
              {"key": "extra", "value": {"stringValue": "val"}}
            ]}
          ]
        }
      ]
    }
  ]
}`, nil)

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.JSONEq(t, `{
  "traces": [
    {
      "spanSets": [
        {
          "spans": [
            {"attributes": [
              {"key": "k8s.namespace.name", "value": {"stringValue": "allowed-ns"}},
              {"key": "extra", "value": {"stringValue": "val"}}
            ]},
            {"attributes": [
              {"key": "k8s.namespace.name", "value": {"stringValue": "blocked-ns"}}
            ]}
          ]
        }
      ]
    }
  ]
}`, string(body))
	})

	t.Run("search tag values endpoint is not modified", func(t *testing.T) {
		resp := makeResponse(ctx, http.StatusOK, "/api/v2/search/tag/resource.service.name/values", `{
  "tagValues": [
    {"type": "string", "value": "frontend"},
    {"type": "string", "value": "backend"}
  ]
}`, nil)

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.JSONEq(t, `{
  "tagValues": [
    {"type": "string", "value": "frontend"},
    {"type": "string", "value": "backend"}
  ]
}`, string(body))
	})

	t.Run("non-matching path is not modified", func(t *testing.T) {
		resp := makeResponse(ctx, http.StatusOK, "/api/echo", "unmodified body", nil)

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "unmodified body", string(body))
	})

	t.Run("non-200 response is not modified", func(t *testing.T) {
		resp := makeResponse(ctx, http.StatusNotFound, "/api/traces/abc123", "error body", nil)

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "error body", string(body))
	})

	t.Run("unhandled filtered API path returns forbidden", func(t *testing.T) {
		// Temporarily add a catch-all to filteredAPIs so a path can pass the
		// filteredAPIs gate but not match any switch case.
		origFiltered := filteredAPIs
		filteredAPIs = append(filteredAPIs, regexp.MustCompile(`^/api/other$`))
		t.Cleanup(func() { filteredAPIs = origFiltered })

		resp := makeResponse(ctx, http.StatusOK, "/api/other", `{"some":"data"}`, nil)

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, "forbidden", string(body))
	})

	t.Run("Content-Length and Content-Encoding headers are updated", func(t *testing.T) {
		resp := makeResponse(ctx, http.StatusOK, "/api/traces/abc123", `{
  "batches": [
    {
      "resource": {
        "attributes": [
          {"key": "k8s.namespace.name", "value": {"stringValue": "allowed-ns"}}
        ]
      },
      "scopeSpans": [
        {"scope": {}, "spans": [{}]}
      ]
    }
  ]
}`, http.Header{"Content-Encoding": []string{"gzip"}})

		require.NoError(t, modifier(resp))

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, []string{fmt.Sprint(len(body))}, resp.Header["Content-Length"])
		assert.Empty(t, resp.Header["Content-Encoding"])
	})
}
