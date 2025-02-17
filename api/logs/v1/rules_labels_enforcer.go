package http

import (
	"encoding/json"
	"errors"
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

			labels, ok := labelKeys[tenant]
			if !ok || len(labels) == 0 {
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

			if httpStatus, err := validateQueryParams(r.URL.Query(), labels, matchers); err != nil {
				httperr.PrometheusAPIError(w, err.Error(), httpStatus)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// validateQueryParams only accepts queries that have all the labels as queryParameters and corresponding values that
// match the matchers. An exception is made for k8s_namespace_name and kubernetes_namespace_name, where only one can be
// present.
func validateQueryParams(queryParams url.Values, labels []string, matchers []*labels.Matcher) (int, error) {
	seenLabels := make(map[string]bool)

	val_k8s := queryParams.Get("k8s_namespace_name")
	val_kubernetes := queryParams.Get("kubernetes_namespace_name")
	if val_k8s != "" && val_kubernetes != "" {
		return http.StatusBadRequest, errors.New("invalid URL parameter cannot specify both kubernetes_namespace_name and k8s_namespace_name")
	}

	for _, label := range labels {
		var (
			val     = queryParams.Get(label)
			matched = false
		)

		// Don't validate the label if the equivalent label is present.
		if label == "kubernetes_namespace_name" && val_k8s != "" || label == "k8s_namespace_name" && val_kubernetes != "" {
			continue
		}

		for _, matcher := range matchers {
			if matcher == nil {
				continue
			}

			if matcher.Name == label && matcher.Matches(val) {
				matched = true
				seenLabels[label] = true
				break
			}
		}

		if !matched {
			return http.StatusUnauthorized, fmt.Errorf("unauthorized access for URL parameter %q and value %q", label, val)
		}
	}

	return http.StatusAccepted, nil
}

// WithParametersAsLabelsFilterRules returns a middleware that transforms query parameters
// that match labelKeys to Loki labels query parameters to filter rules.
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
