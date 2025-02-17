package v1

import (
	"testing"

	"github.com/grafana/tempo/pkg/tempopb"
	commonv1 "github.com/grafana/tempo/pkg/tempopb/common/v1"
	resourcev1 "github.com/grafana/tempo/pkg/tempopb/resource/v1"
	tracev1 "github.com/grafana/tempo/pkg/tempopb/trace/v1"
	"github.com/stretchr/testify/assert"
)

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

func createStringAttribute(key string, value string) *commonv1.KeyValue {
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
