package authorization

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/rbac"
)

// WithAuthorizers returns a middleware that authorizes subjects taken from a request context
// for the given permission on the given resource for a tenant taken from a request context.
func WithAuthorizers(authorizers map[string]rbac.Authorizer, permission rbac.Permission, resource string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				http.Error(w, "error finding tenant", http.StatusInternalServerError)

				return
			}
			subject, ok := authentication.GetSubject(r.Context())
			if !ok {
				http.Error(w, "unknown subject", http.StatusUnauthorized)

				return
			}
			groups, ok := authentication.GetGroups(r.Context())
			if !ok {
				groups = []string{}
			}
			a, ok := authorizers[tenant]
			if !ok {
				http.Error(w, "error finding tenant", http.StatusUnauthorized)

				return
			}

			if statusCode, ok := a.Authorize(subject, groups, permission, resource, tenant); !ok {
				w.WriteHeader(statusCode)

				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceTenantLabel returns a middleware that ensures that every query
// has a tenant label enforced.
func WithEnforceTenantLabel(label string) func(http.Handler) http.Handler {
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

const queryParam = "query"

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
