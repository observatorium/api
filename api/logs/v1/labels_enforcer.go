package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

// TODO: share with OPA?
type MatchersInfo struct {
	Matchers  []*labels.Matcher `json:"matchers,omitempty"`
	LogicalOp string            `json:"logicalOp,omitempty"`
}

const logicalOr = "or"

// WithEnforceAuthorizationLabels return a middleware that ensures every query
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

			var matchersInfo MatchersInfo
			if err := json.Unmarshal([]byte(data), &matchersInfo); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matchers", http.StatusInternalServerError)

				return
			}

			q, err := enforceValues(matchersInfo, r.URL.Query())
			if err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce authorization label matchers: %v", err), http.StatusInternalServerError)

				return
			}
			r.URL.RawQuery = q

			next.ServeHTTP(w, r)
		})
	}
}

const queryParam = "query"

func enforceValues(mInfo MatchersInfo, v url.Values) (values string, err error) {
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
			if mInfo.LogicalOp == logicalOr {
				le.AppendORMatchers(mInfo.Matchers)
			} else {
				le.AppendMatchers(mInfo.Matchers)
			}
		default:
			// Do nothing
		}
	})

	v.Set(queryParam, expr.String())

	return v.Encode(), nil
}
