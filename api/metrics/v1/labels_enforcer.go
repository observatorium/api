package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"
)

const (
	queryParam    = "query"
	matchersParam = "match[]"
)

// WithEnforceTenancyOnQuery returns a middleware that ensures that every query has a tenant label enforced.
func WithEnforceTenancyOnQuery(label string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Adapted from
		// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := authentication.GetTenantID(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusInternalServerError)

				return
			}

			e := injectproxy.NewEnforcer(false, []*labels.Matcher{{
				Name:  label,
				Type:  labels.MatchEqual,
				Value: id,
			}}...)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, w, r); !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceTenancyOnMatchers returns a middleware that ensures that every matchers has a tenant label enforced.
// This middleware has to be able to handle both GET and POST requests, because according to Prometheus' documentation
// the `label_names` and `series` endpoints support GET and POST requests. The `label_values` endpoint supports only GET.
// When handling GET requests, query parameters are used, modified accordingly and proxied down.
// When handling POST requests if it contains query parameters, they will be transformed into form data before being
// proxied. Incoming form data always has higher priority over query parameters.
func WithEnforceTenancyOnMatchers(tenantLabel string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// matcher ensures all the provided match[] if any has label injected. If none was provided,
		// single matcher is injected. This works for non-query Prometheus APIs like: /api/v1/series,
		// /api/v1/label/<name>/values, /api/v1/labels and /federate support multiple matchers.
		// See e.g https://prometheus.io/docs/prometheus/latest/querying/api/#querying-metadata
		// Adapted from
		// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go#L318.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID, ok := authentication.GetTenantID(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusInternalServerError)

				return
			}

			tenantMatcher := &labels.Matcher{
				Name:  tenantLabel,
				Type:  labels.MatchEqual,
				Value: tenantID,
			}

			err := r.ParseForm()
			if err != nil {
				httperr.PrometheusAPIError(w, "error parsing form", http.StatusBadRequest)
				return
			}

			formMatchers := r.Form[matchersParam]

			if len(formMatchers) == 0 {
				r.Form.Set(matchersParam, matchersToString(tenantMatcher))
			} else {
				// Inject label to existing matchers.
				for i, rawMatcher := range formMatchers {
					matcher, err := parser.ParseMetricSelector(rawMatcher)
					if err != nil {
						httperr.PrometheusAPIError(w, "error parsing matchers", http.StatusBadRequest)
						return
					}
					formMatchers[i] = matchersToString(append(matcher, tenantMatcher)...)
				}
				r.Form[matchersParam] = formMatchers
			}

			// Update the content length headers to avoid proxying errors.
			if r.Method == http.MethodPost {
				encodedForm := r.Form.Encode()
				r.Body = io.NopCloser(bytes.NewBufferString(encodedForm))
				r.ContentLength = int64(len(encodedForm))
				r.Header.Set("Content-Length", strconv.Itoa(len(encodedForm)))
			}

			if r.Method == http.MethodGet {
				q := r.URL.Query()
				q.Set(matchersParam, matchersToString(tenantMatcher))
				r.URL.RawQuery = q.Encode()
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceAuthorizationLabels returns a middleware that ensures every query
// has a set of labels returned by the OPA authorizer enforced.
func WithEnforceAuthorizationLabels() func(http.Handler) http.Handler {
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

			var lm []*labels.Matcher
			if err := json.Unmarshal([]byte(data), &lm); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matcher", http.StatusInternalServerError)

				return
			}

			e := injectproxy.NewEnforcer(false, lm...)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, w, r); !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func enforceRequestQueryLabels(e *injectproxy.Enforcer, w http.ResponseWriter, r *http.Request) bool {
	// The `query` can come in the URL query string and/or the POST body.
	// For this reason, we need to try to enforcing in both places.
	// Note: a POST request may include some values in the URL query string
	// and others in the body. If both locations include a `query`, then
	// enforce in both places.
	q, foundQuery, err := enforceQueryValues(e, r.URL.Query())
	if err != nil {
		httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce labels: %v", err), http.StatusBadRequest)

		return false
	}

	r.URL.RawQuery = q

	var foundForm bool
	// Enforce the query in the POST body if needed.
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			// We're returning server error here because we cannot ensure this is a bad request.
			httperr.PrometheusAPIError(w, fmt.Sprintf("could not parse form: %v", err), http.StatusInternalServerError)

			return false
		}

		q, foundForm, err = enforceQueryValues(e, r.PostForm)
		if err != nil {
			httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce labels: %v", err), http.StatusBadRequest)

			return false
		}
		// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
		_ = r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(q))
		r.ContentLength = int64(len(q))
	}

	// If no query was found, return early.
	if !foundQuery && !foundForm {
		httperr.PrometheusAPIError(w, "no query found", http.StatusBadRequest)

		return false
	}

	return true
}

// Adapted from
// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
func enforceQueryValues(e *injectproxy.Enforcer, v url.Values) (values string, foundQuery bool, err error) {
	// If no values were given or no query is present,
	// e.g. because the query came in the POST body
	// but the URL query string was passed, then finish early.
	// PROBLEM HERE! Only gets first value.
	if v.Get(queryParam) == "" {
		return v.Encode(), false, nil
	}

	expr, err := parser.ParseExpr(v.Get(queryParam))
	if err != nil {
		return "", true, fmt.Errorf("parse expr error: %w", err)
	}

	if err := e.EnforceNode(expr); err != nil {
		return "", true, fmt.Errorf("enforce node error: %w", err)
	}

	v.Set(queryParam, expr.String())

	return v.Encode(), true, nil
}

func matchersToString(ms ...*labels.Matcher) string {
	el := make([]string, 0, len(ms))
	for _, m := range ms {
		el = append(el, m.String())
	}

	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}
