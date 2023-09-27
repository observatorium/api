package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"
	"github.com/prometheus/prometheus/model/labels"
)

const (
	labelsParam      = "labels"
	matcherNamespace = "kubernetes_namespace_name"
	namespaceLabel   = "namespace"
)

// WithEnforceRulesLabelFilters returns a middleware that enforces that every query
// parameter has a matching matcher returned by authorization endpoint.
func WithEnforceRulesLabelFilters(labelKeys map[string][]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "missing tenant id", http.StatusBadRequest)

				return
			}

			keys, ok := labelKeys[tenant]
			if !ok || len(keys) == 0 {
				next.ServeHTTP(w, r)

				return
			}

			data, ok := authorization.GetData(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding authorization label matcher", http.StatusInternalServerError)

				return
			}

			// Early pass to the next if no authz label enforcement configured.
			if data == "" {
				next.ServeHTTP(w, r)

				return
			}

			var matchersInfo AuthzResponseData
			if err := json.Unmarshal([]byte(data), &matchersInfo); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matchers", http.StatusInternalServerError)

				return
			}

			matchers, err := initAuthzMatchers(matchersInfo.Matchers)
			if err != nil {
				httperr.PrometheusAPIError(w, "error initializing authorization label matchers", http.StatusInternalServerError)

				return
			}

			// If the authorization endpoint provides any matchers, ensure that the URL parameter value
			// matches an authorization matcher with the same URL parameter key.
			queryParams := r.URL.Query()
			for _, key := range keys {
				var (
					val     = queryParams.Get(key)
					matched = false
				)

				for _, matcher := range matchers {
					if matcher == nil {
						continue
					}

					if matcher.Name == key && matcher.Matches(val) {
						matched = true
						break
					}
				}

				if !matched {
					httperr.PrometheusAPIError(w, fmt.Sprintf("unauthorized access for URL parameter %q and value %q", key, val), http.StatusForbidden)

					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceNamespaceLabels returns a middleware that adds a query parameter
// to a request to filter by namespace labels.
func WithEnforceRulesNamespaceLabelFilter() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := authorization.GetData(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding authorization label matcher", http.StatusInternalServerError)

				return
			}

			// Early pass to the next if no authz
			// label enforcement configured.
			if data == "" {
				next.ServeHTTP(w, r)

				return
			}

			var matchersInfo AuthzResponseData
			if err := json.Unmarshal([]byte(data), &matchersInfo); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matchers", http.StatusInternalServerError)

				return
			}

			r.URL.RawQuery = enforceNamespaceLabels(matchersInfo.Matchers, r.URL.Query())

			next.ServeHTTP(w, r)

		})
	}
}

func enforceNamespaceLabels(matchers []*labels.Matcher, v url.Values) string {
	ls := make([]string, 0)
	for _, m := range matchers {
		// OPA returns a "|" delimited list of namespaces.
		if m != nil && m.Name == matcherNamespace && (m.Type == labels.MatchEqual || m.Type == labels.MatchRegexp) {
			ns := strings.Split(m.Value, "|")
			for _, n := range ns {
				ls = append(ls, fmt.Sprintf("%s:%s", namespaceLabel, n))
			}
		}
	}

	if len(ls) > 0 {
		v.Set(labelsParam, strings.Join(ls, ","))
	}

	return v.Encode()
}
