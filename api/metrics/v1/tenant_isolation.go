package v1

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/observatorium/api/authentication"
	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql/parser"
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
				http.Error(w, "error finding tenant ID", http.StatusInternalServerError)
				return
			}

			e := injectproxy.NewEnforcer([]*labels.Matcher{{
				Name:  label,
				Type:  labels.MatchEqual,
				Value: id,
			}}...)

			// The `query` can come in the URL query string and/or the POST body.
			// For this reason, we need to try to enforcing in both places.
			// Note: a POST request may include some values in the URL query string
			// and others in the body. If both locations include a `query`, then
			// enforce in both places.
			q, found1, err := enforceQueryValues(e, r.URL.Query())
			if err != nil {
				http.Error(w, fmt.Sprintf("could not enforce tenant label: %v", err), http.StatusInternalServerError)
				return
			}
			r.URL.RawQuery = q

			var found2 bool
			// Enforce the query in the POST body if needed.
			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err != nil {
					http.Error(w, fmt.Sprintf("could not parse form: %v", err), http.StatusInternalServerError)
					return
				}
				q, found2, err = enforceQueryValues(e, r.PostForm)
				if err != nil {
					http.Error(w, fmt.Sprintf("could not enforce tenant label: %v", err), http.StatusInternalServerError)
					return
				}
				// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
				_ = r.Body.Close()
				r.Body = ioutil.NopCloser(strings.NewReader(q))
				r.ContentLength = int64(len(q))
			}

			// If no query was found, return early.
			if !found1 && !found2 {
				http.Error(w, "no query found", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Adapted from
// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
func enforceQueryValues(e *injectproxy.Enforcer, v url.Values) (values string, foundQuery bool, err error) {
	// If no values were given or no query is present,
	// e.g. because the query came in the POST body
	// but the URL query string was passed, then finish early.
	if v.Get(queryParam) == "" {
		return v.Encode(), false, nil
	}

	expr, err := parser.ParseExpr(v.Get(queryParam))
	if err != nil {
		return "", true, err
	}

	if err := e.EnforceNode(expr); err != nil {
		return "", true, err
	}

	v.Set(queryParam, expr.String())

	return v.Encode(), true, nil
}

// WithEnforceTenancyOnMatchers returns a middleware that ensures that every matchers has a tenant label enforced.
func WithEnforceTenancyOnMatchers(label string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// matcher ensures all the provided match[] if any has label injected. If none was provided,
		// single matcher is injected. This works for non-query Prometheus APIs like: /api/v1/series,
		// /api/v1/label/<name>/values, /api/v1/labels and /federate support multiple matchers.
		// See e.g https://prometheus.io/docs/prometheus/latest/querying/api/#querying-metadata
		// Adapted from
		// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go#L318.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := authentication.GetTenantID(r.Context())
			if !ok {
				http.Error(w, "error finding tenant ID", http.StatusInternalServerError)
				return
			}

			matcher := &labels.Matcher{
				Name:  label,
				Type:  labels.MatchEqual,
				Value: id,
			}

			q := r.URL.Query()
			matchers := q[matchersParam]

			if len(matchers) == 0 {
				q.Set(matchersParam, matchersToString(matcher))
			} else {
				// Inject label to existing matchers.
				for i, m := range matchers {
					ms, err := parser.ParseMetricSelector(m)
					if err != nil {
						return
					}
					matchers[i] = matchersToString(append(ms, matcher)...)
				}
				q[matchersParam] = matchers
			}

			r.URL.RawQuery = q.Encode()
			next.ServeHTTP(w, r)
		})
	}
}

func matchersToString(ms ...*labels.Matcher) string {
	el := make([]string, 0, len(ms))
	for _, m := range ms {
		el = append(el, m.String())
	}

	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}
