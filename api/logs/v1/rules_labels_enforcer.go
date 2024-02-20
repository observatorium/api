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

const labelsParam = "labels"

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

// WithParametersAsLabelsFilterRules returns a middleware that transforms query parameters
// that match the CLI arg labelKeys to the native Loki labels query parameters.
func WithParametersAsLabelsFilterRules(labelKeys map[string][]string) func(http.Handler) http.Handler {
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

			r.URL.RawQuery = transformParametersInLabelFilter(keys, matchers, r.URL.Query())

			next.ServeHTTP(w, r)

		})
	}
}

func transformParametersInLabelFilter(keys []string, matchers []*labels.Matcher, queryParams url.Values) string {
	var labelFilter []string
	for _, key := range keys {
		val := queryParams.Get(key)

		for _, matcher := range matchers {
			if matcher == nil {
				continue
			}

			if matcher.Name == key && matcher.Matches(val) {
				labelFilter = append(labelFilter, fmt.Sprintf("%s:%s", key, val))
				queryParams.Del(key)
				break
			}
		}
	}

	if len(labelFilter) == 0 {
		return queryParams.Encode()
	}

	queryParams.Set(labelsParam, strings.Join(labelFilter, ","))
	return queryParams.Encode()
}
