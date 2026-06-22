package v1

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/golang/protobuf/jsonpb" // nolint:staticcheck
	"github.com/grafana/tempo/pkg/tempopb"
	commonv1 "github.com/grafana/tempo/pkg/tempopb/common/v1"
	tracev1 "github.com/grafana/tempo/pkg/tempopb/trace/v1"

	apilogsv1 "github.com/observatorium/api/api/logs/v1"
)

const (
	namespaceAttributeKey = "k8s.namespace.name"
	serviceAttributeKey   = "service.name"
)

var allowedTempoAPIs = []*regexp.Regexp{
	regexp.MustCompile(`^/api/traces/\w+$`),
	regexp.MustCompile(`^/api/search$`),
}

func matchesAnyRegex(s string, patterns []*regexp.Regexp) bool {
	for _, re := range patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func WithTraceQLNamespaceSelectAndForbidOtherAPIs(enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}

			// This middleware is registered at /tempo/...
			requestedTempoPath := strings.TrimPrefix(r.URL.Path, "/tempo")

			if !matchesAnyRegex(requestedTempoPath, allowedTempoAPIs) {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if requestedTempoPath == "/api/search" {
				query := r.URL.Query()
				q := query.Get("q")
				traceQL, err := url.QueryUnescape(q)
				if err != nil {
					next.ServeHTTP(w, r)
					return
				}
				if traceQL == "" {
					traceQL = "{ }"
				}
				traceQL = traceQL + " | select(resource.k8s.namespace.name)"
				query.Set("q", traceQL)
				r.URL.RawQuery = query.Encode()
			}

			next.ServeHTTP(w, r)
		})
	}
}

func responseRBACModifier(log log.Logger) func(response *http.Response) error {
	return func(response *http.Response) error {
		if strings.HasPrefix(response.Request.URL.Path, "/api/traces/") || strings.HasPrefix(response.Request.URL.Path, "/api/search") {
			allowedNamespaces := map[string]bool{}
			namespaces := apilogsv1.AllowedNamespaces(response.Request.Context())
			for _, ns := range namespaces {
				allowedNamespaces[ns] = true
			}
			level.Debug(log).Log("AllowedNamespaces", fmt.Sprintf("%v", allowedNamespaces))

			if response.StatusCode == http.StatusOK {
				b, err := io.ReadAll(response.Body)
				if err != nil {
					return err
				}

				responseBuffer := &bytes.Buffer{}
				if strings.HasPrefix(response.Request.URL.Path, "/api/traces/") {
					trace := &tempopb.Trace{}
					err = tempopb.UnmarshalFromJSONV1(b, trace)
					if err != nil {
						return err
					}
					trace = traceRBAC(allowedNamespaces, trace)

					traceResponseBody, err := tempopb.MarshalToJSONV1(trace)
					if err != nil {
						return err
					}
					responseBuffer = bytes.NewBuffer(traceResponseBody)
				} else {
					searchResponse := &tempopb.SearchResponse{}
					err = jsonpb.UnmarshalString(string(b), searchResponse)
					if err != nil {
						return err
					}
					searchResponse = searchResponseRBAC(allowedNamespaces, searchResponse)

					marshaller := jsonpb.Marshaler{}
					err = marshaller.Marshal(responseBuffer, searchResponse)
					if err != nil {
						return err
					}
				}
				response.Body = io.NopCloser(responseBuffer)
				response.Header["Content-Length"] = []string{fmt.Sprint(responseBuffer.Len())}
				// We could re-encode in gzip/deflate, but there is no need, so send it raw
				response.Header["Content-Encoding"] = []string{}
			}

			return nil
		}

		return nil
	}
}

func traceRBAC(allowedNamespaces map[string]bool, trace *tempopb.Trace) *tempopb.Trace {
	for _, rs := range trace.ResourceSpans {
		notAllowedNamespace := ""
		missingNamespaceAttribute := true
		if rs.Resource != nil && rs.Resource.Attributes != nil {
			for _, resAttr := range rs.Resource.Attributes {
				if resAttr.Key == namespaceAttributeKey {
					missingNamespaceAttribute = false
					if !allowedNamespaces[resAttr.Value.GetStringValue()] {
						notAllowedNamespace = resAttr.Value.GetStringValue()
						for _, scopeSpan := range rs.ScopeSpans {
							scopeSpan.Scope.Attributes = []*commonv1.KeyValue{}
							for _, span := range scopeSpan.Spans {
								span.Attributes = []*commonv1.KeyValue{}
								span.Events = []*tracev1.Span_Event{}
							}
						}
					}
				}
			}
			// when resource attribute is missing, all attributes are removed
			if missingNamespaceAttribute {
				serviceAttribute := getAttribute(rs.Resource.Attributes, serviceAttributeKey)
				rs.Resource.Attributes = []*commonv1.KeyValue{}
				if serviceAttribute != nil {
					rs.Resource.Attributes = append(rs.Resource.Attributes, serviceAttribute)
				}
				for _, scopeSpan := range rs.ScopeSpans {
					scopeSpan.Scope.Attributes = []*commonv1.KeyValue{}
					for _, span := range scopeSpan.Spans {
						span.Attributes = []*commonv1.KeyValue{}
						span.Events = []*tracev1.Span_Event{}
					}
				}
			}
			// add namespace back if it was not allowed
			if notAllowedNamespace != "" {
				serviceAttribute := getAttribute(rs.Resource.Attributes, serviceAttributeKey)
				rs.Resource.Attributes = []*commonv1.KeyValue{}
				rs.Resource.Attributes = append(rs.Resource.Attributes, &commonv1.KeyValue{
					Key:   namespaceAttributeKey,
					Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: notAllowedNamespace}},
				})
				rs.Resource.Attributes = append(rs.Resource.Attributes, serviceAttribute)
			}
		}
	}
	return trace
}

func getAttribute(attributes []*commonv1.KeyValue, key string) *commonv1.KeyValue {
	for _, attr := range attributes {
		if attr.GetKey() == key {
			return attr
		}
	}
	return nil
}

func searchResponseRBAC(allowedNamespaces map[string]bool, searchResponse *tempopb.SearchResponse) *tempopb.SearchResponse {
	for _, traceSearchMetadata := range searchResponse.GetTraces() {
		for i := range traceSearchMetadata.GetSpanSets() {
			traceSearchMetadata.SpanSets[i] = spanSetRBAC(allowedNamespaces, traceSearchMetadata.SpanSets[i])
		}
		traceSearchMetadata.SpanSet = spanSetRBAC(allowedNamespaces, traceSearchMetadata.GetSpanSet())
	}
	return searchResponse
}

func spanSetRBAC(allowedNamespaces map[string]bool, spanSet *tempopb.SpanSet) *tempopb.SpanSet {
	for _, span := range spanSet.GetSpans() {
		notAllowedNamespace := ""
		missingNamespaceAttribute := true
		for _, attribute := range span.GetAttributes() {
			if attribute.GetKey() == namespaceAttributeKey {
				missingNamespaceAttribute = false
				if !allowedNamespaces[attribute.GetValue().GetStringValue()] {
					notAllowedNamespace = attribute.GetValue().GetStringValue()
				}
			}
		}
		if missingNamespaceAttribute {
			span.Attributes = []*commonv1.KeyValue{}
		}
		// remove attributes because span is from not allowed namespace
		if notAllowedNamespace != "" {
			span.Attributes = []*commonv1.KeyValue{}
			span.Attributes = append(span.Attributes, &commonv1.KeyValue{
				Key:   namespaceAttributeKey,
				Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: notAllowedNamespace}},
			})
		}
	}
	return spanSet
}
