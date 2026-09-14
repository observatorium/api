package authorization

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/httperr"
)

// WithTenantLabel returns a middleware that converts tenant(s) from the request context
// into label matchers for enforcement by label enforcer middlewares.
// Supports single tenant or multiple tenants separated by |.
func WithTenantLabel(tenantLabelName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant", http.StatusBadRequest)
				return
			}

			// Support multiple tenants separated by |
			// e.g., "tenant-a|tenant-b|tenant-c"
			tenants := strings.Split(tenant, "|")

			var matchers []*labels.Matcher
			if len(tenants) == 1 {
				// Single tenant: exact match
				matchers = []*labels.Matcher{
					{
						Type:  labels.MatchEqual,
						Name:  tenantLabelName,
						Value: tenants[0],
					},
				}
			} else {
				// Multiple tenants: regex match with OR
				// Creates: tenant_id=~"tenant-a|tenant-b|tenant-c"
				matchers = []*labels.Matcher{
					{
						Type:  labels.MatchRegexp,
						Name:  tenantLabelName,
						Value: strings.Join(tenants, "|"),
					},
				}
			}

			// Serialize matchers to JSON for label enforcers
			matchersJSON, err := json.Marshal(matchers)
			if err != nil {
				httperr.PrometheusAPIError(w, "error encoding tenant matchers", http.StatusInternalServerError)
				return
			}

			// Set in authorization context for label enforcers to use
			ctx := WithData(r.Context(), string(matchersJSON))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
