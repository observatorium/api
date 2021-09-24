package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/observatorium/api/authorization"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/pkg/labels"
)

// WithEnforceAuthorizationLabels return a middleware that ensures every query
// has a set of labels returned by the OPA authorizer enforced.
func WithEnforceAuthorizationLabels() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := authorization.GetData(r.Context())
			if !ok {
				http.Error(w, "error finding authorization label matcher", http.StatusInternalServerError)

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
				http.Error(w, "error parsing authorization label matcher", http.StatusInternalServerError)

				return
			}

			q, err := enforceValues(lm, r.URL.Query())
			if err != nil {
				http.Error(w, fmt.Sprintf("could not enforce authorization label matchers: %v", err), http.StatusInternalServerError)

				return
			}
			r.URL.RawQuery = q

			next.ServeHTTP(w, r)
		})
	}
}

const queryParam = "query"

func enforceValues(lm []*labels.Matcher, v url.Values) (values string, err error) {
	if v.Get(queryParam) == "" {
		return v.Encode(), nil
	}

	expr, err := logqlv2.ParseExpr(v.Get(queryParam))
	if err != nil {
		return "", fmt.Errorf("failed parsing LogQL expression: %w", err)
	}

	expr.Walk(func(expr interface{}) {
		switch le := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			le.AppendMatchers(lm)
		default:
			// Do nothing
		}
	})

	v.Set(queryParam, expr.String())

	return v.Encode(), nil
}
