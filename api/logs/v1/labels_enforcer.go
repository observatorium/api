package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

type AuthzResponseData struct {
	Matchers  []*labels.Matcher `json:"matchers,omitempty"`
	MatcherOp string            `json:"matcherOp,omitempty"`
}

const (
	logicalOr  = "or"
	queryParam = "query"
	matchParam = "match"
)

type matchersContextKey struct{}

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

			var matchersInfo AuthzResponseData
			if err := json.Unmarshal([]byte(data), &matchersInfo); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matchers", http.StatusInternalServerError)

				return
			}
			r = r.WithContext(context.WithValue(r.Context(), matchersContextKey{}, matchersInfo))

			q, err := enforceValues(matchersInfo, r.URL)
			if err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce authorization label matchers: %v", err), http.StatusInternalServerError)

				return
			}
			r.URL.RawQuery = q

			next.ServeHTTP(w, r)
		})
	}
}

func enforceValues(mInfo AuthzResponseData, u *url.URL) (values string, err error) {
	switch {
	case strings.HasSuffix(u.Path, "/values"):
		return enforceValuesOnFilter(mInfo, u.Query(), queryParam)
	case strings.HasSuffix(u.Path, "/series"):
		return enforceValuesOnFilter(mInfo, u.Query(), matchParam)
	default:
		return enforceValuesOnQuery(mInfo, u.Query())
	}
}

func enforceValuesOnFilter(mInfo AuthzResponseData, v url.Values, filterParam string) (values string, err error) {

	lm, err := initAuthzMatchers(mInfo.Matchers)
	if err != nil {
		return "", err
	}

	var expr logqlv2.Expr

	if q := v.Get(filterParam); q != "" {
		expr, err = logqlv2.ParseExpr(q)
		if err != nil {
			return "", fmt.Errorf("failed parsing LogQL expression: %w", err)
		}

		if le, ok := expr.(*logqlv2.LogQueryExpr); ok {
			matchers := combineLabelMatchers(le.Matchers(), lm)
			le.SetMatchers(matchers)
		}
	} else {
		expr = &logqlv2.StreamMatcherExpr{}
		expr.(*logqlv2.StreamMatcherExpr).SetMatchers(lm)
	}

	v.Set(filterParam, expr.String())

	return v.Encode(), nil
}

func enforceValuesOnQuery(mInfo AuthzResponseData, v url.Values) (values string, err error) {
	if v.Get(queryParam) == "" {
		return v.Encode(), nil
	}

	lm, err := initAuthzMatchers(mInfo.Matchers)
	if err != nil {
		return "", err
	}

	expr, err := logqlv2.ParseExpr(v.Get(queryParam))
	if err != nil {
		return "", fmt.Errorf("failed parsing LogQL expression: %w", err)
	}

	switch mInfo.MatcherOp {
	case logicalOr:
		// Logical "OR" to combine multiple matchers needs to be done via LogQueryExpr > LogPipelineExpr
		expr.Walk(func(expr interface{}) {
			switch le := expr.(type) {
			case *logqlv2.LogQueryExpr:
				le.AppendPipelineMatchers(mInfo.Matchers, logicalOr)
			default:
				// Do nothing
			}
		})
	default:
		expr.Walk(func(expr interface{}) {
			switch le := expr.(type) {
			case *logqlv2.StreamMatcherExpr:
				matchers := combineLabelMatchers(le.Matchers(), lm)
				le.SetMatchers(matchers)
			default:
				// Do nothing
			}
		})
	}

	v.Set(queryParam, expr.String())

	return v.Encode(), nil
}

// Combine the query label matcher and the authorization label matcher.
func combineLabelMatchers(queryMatchers, authzMatchers []*labels.Matcher) []*labels.Matcher {
	queryMatchersMap := make(map[string]*labels.Matcher)
	for _, qm := range queryMatchers {
		queryMatchersMap[qm.Name] = qm
	}

	matchers := make([]*labels.Matcher, 0)
	for _, am := range authzMatchers {
		qm := queryMatchersMap[am.Name]
		if qm == nil || !am.Matches(qm.Value) {
			queryMatchersMap[am.Name] = am
		}
	}

	for _, m := range queryMatchersMap {
		matchers = append(matchers, m)
	}

	return matchers
}

func initAuthzMatchers(lm []*labels.Matcher) ([]*labels.Matcher, error) {
	// Fix label matchers to include a non nil FastRegexMatcher for regex types.
	for i, m := range lm {
		nm, err := labels.NewMatcher(m.Type, m.Name, m.Value)
		if err != nil {
			return nil, fmt.Errorf("failed parsing label matcher: %w", err)
		}

		lm[i] = nm
	}

	return lm, nil
}

// AllowedNamespaces returns the list of namespaces that the user is allowed to list.
func AllowedNamespaces(ctx context.Context) []string {
	matchers := ctx.Value(matchersContextKey{})
	if matchers == nil {
		return nil
	}
	matchersTyped := matchers.(AuthzResponseData)

	var namespaces []string
	for _, m := range matchersTyped.Matchers {
		namespaces = append(namespaces, strings.Split(m.Value, "|")...)
	}
	return namespaces
}
