package v1

import (
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

// WithEnforceTenancyOnQuery returns a middleware that ensures that every query has a tenant label enforced.
func WithEnforceTenancyOnQuery(tenantLabel, paramName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Adapted from
		// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
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
			e := injectproxy.NewPromQLEnforcer(false, tenantMatcher)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, paramName, w, r); !ok {
				return
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

			e := injectproxy.NewPromQLEnforcer(false, lm...)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, "query", w, r); !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func enforceRequestQueryLabels(e *injectproxy.PromQLEnforcer, paramName string, w http.ResponseWriter, r *http.Request) bool {
	// The `query` can come in the URL query string and/or the POST body.
	// For this reason, we need to try to enforcing in both places.
	// Note: a POST request may include some values in the URL query string
	// and others in the body. If both locations include a `query`, then
	// enforce in both places.
	q, foundQuery, err := enforceQueryValues(e, paramName, r.URL.Query())
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

		q, foundForm, err = enforceQueryValues(e, paramName, r.PostForm)
		if err != nil {
			httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce labels: %v", err), http.StatusBadRequest)

			return false
		}
		// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
		_ = r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(q))
		r.ContentLength = int64(len(q))
		r.Header.Set("Content-Length", strconv.Itoa(len(q)))
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
func enforceQueryValues(e *injectproxy.PromQLEnforcer, paramName string, requestParams url.Values) (values string, foundQuery bool, err error) {
	if len(requestParams[paramName]) == 0 {
		// This is a dirty hack to force the introduction of a match[] param to add tenancy
		// enforcement even when the param isn't present. This is needed because match[] is
		// optional for label names and values, yet we have to add it to avoid leaks.
		// Would love to find a cleaner way to do it.
		enforcedMatchers, err := e.EnforceMatchers([]*labels.Matcher{})
		if err != nil {
			return "", false, fmt.Errorf("enforce matchers error: %w", err)
		}
		requestParams.Set(paramName, matchersToString(enforcedMatchers...))
		return requestParams.Encode(), true, nil
	}

	matchers := requestParams[paramName]
	for i, rawMatcher := range matchers {
		expr, err := parser.ParseExpr(rawMatcher)
		if err != nil {
			return "", true, fmt.Errorf("parse expr error: %w", err)
		}
		if err := e.EnforceNode(expr); err != nil {
			return "", true, fmt.Errorf("enforce node error: %w", err)
		}
		matchers[i] = expr.String()
	}
	return requestParams.Encode(), true, nil
}

func matchersToString(ms ...*labels.Matcher) string {
	el := make([]string, 0, len(ms))
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}
