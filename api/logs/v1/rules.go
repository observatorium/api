package http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/ghodss/yaml"
	"github.com/go-chi/chi"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/httperr"
	"github.com/observatorium/api/rules"
)

// WithEnforceTenantAsRuleNamespace returns a middleware that ensures that the
// namespace given on loki namespaced rule routes is the same as the tenant name.
func WithEnforceTenantAsRuleNamespace() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusUnauthorized)
				return
			}

			rctx := chi.RouteContext(r.Context())
			if rctx == nil {
				httperr.PrometheusAPIError(w, "error finding route context", http.StatusInternalServerError)
				return
			}

			// Exclude ruler discovery calls from Grafana:
			// See: https://github.com/grafana/grafana/blob/842ce144292bdf6b51ba2e13961c0986969005e4/public/app/features/alerting/unified/api/ruler.ts#L93-L100
			group := chi.URLParam(r, "groupName")
			namespace := chi.URLParam(r, "namespace")
			if namespace == "test" && group == "test" {
				httperr.PrometheusAPIError(w, "page not found", http.StatusNotFound)
				return
			}

			if namespace != "" && tenant != namespace {
				httperr.PrometheusAPIError(w, "error tenant not matching namespace", http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceRuleLabels returns a middleware that ensures every rule includes
// the tenant label.
func WithEnforceRuleLabels(tenantLabel string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := authentication.GetTenantID(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusUnauthorized)
				return
			}

			defer r.Body.Close()

			group, err := unmarshalRuleGroup(r.Body)
			if err != nil {
				httperr.PrometheusAPIError(w, "error unmarshalling rule group", http.StatusInternalServerError)
				return
			}

			err = enforceLabelsInRules(&group, tenantLabel, id)
			if err != nil {
				httperr.PrometheusAPIError(w, "error enforing labels into rules", http.StatusInternalServerError)
				return
			}

			body, err := yaml.Marshal(group)
			if err != nil {
				httperr.PrometheusAPIError(w, "error marshaling rules YAML", http.StatusInternalServerError)
				return
			}

			nr := r.Clone(r.Context())
			nr.Body = io.NopCloser(bytes.NewReader(body))
			nr.ContentLength = int64(len(body))

			next.ServeHTTP(w, nr)
		})
	}
}

func unmarshalRuleGroup(r io.Reader) (rules.RuleGroup, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return rules.RuleGroup{}, err
	}

	var rg rules.RuleGroup
	if err := yaml.Unmarshal(body, &rg); err != nil {
		return rules.RuleGroup{}, err
	}

	return rg, nil
}

func enforceLabelsInRules(rg *rules.RuleGroup, tenantLabel, tenantID string) error {
	for i := range rg.Rules {
		switch r := rg.Rules[i].(type) {
		case rules.RecordingRule:
			if r.Labels.AdditionalProperties == nil {
				r.Labels.AdditionalProperties = make(map[string]string)
			}

			r.Labels.AdditionalProperties[tenantLabel] = tenantID
			rg.Rules[i] = r
		case rules.AlertingRule:
			if r.Labels.AdditionalProperties == nil {
				r.Labels.AdditionalProperties = make(map[string]string)
			}

			r.Labels.AdditionalProperties[tenantLabel] = tenantID
			rg.Rules[i] = r
		default:
			return fmt.Errorf("failed to convert rule type: %#v", r)
		}
	}

	return nil
}
