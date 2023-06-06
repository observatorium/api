package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ghodss/yaml"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/httperr"
	"github.com/prometheus/prometheus/model/labels"
)

const (
	contentTypeApplicationJSON = "application/json"
	contentTypeApplicationYAML = "application/yaml"
)

var (
	errUnknownTenantKey        = errors.New("Unknown tenant key")
	errUnknownRulesContentType = errors.New("Unknown rules response content type")
)

type alert struct {
	Labels      labels.Labels `json:"labels"`
	Annotations labels.Labels `json:"annotations"`
	State       string        `json:"state"`
	ActiveAt    *time.Time    `json:"activeAt,omitempty"`
	Value       string        `json:"value"`
}

func (a *alert) GetLabels() labels.Labels { return a.Labels }

type alertingRule struct {
	Name        string        `json:"name"`
	Query       string        `json:"query"`
	Duration    float64       `json:"duration"`
	Labels      labels.Labels `json:"labels"`
	Annotations labels.Labels `json:"annotations"`
	Alerts      []*alert      `json:"alerts"`
	Health      string        `json:"health"`
	LastError   string        `json:"lastError,omitempty"`
	// Type of an alertingRule is always "alerting".
	Type string `json:"type"`
}

type recordingRule struct {
	Name      string        `json:"name"`
	Query     string        `json:"query"`
	Labels    labels.Labels `json:"labels,omitempty"`
	Health    string        `json:"health"`
	LastError string        `json:"lastError,omitempty"`
	// Type of a recordingRule is always "recording".
	Type string `json:"type"`
}

type ruleGroup struct {
	Name     string  `json:"name"`
	File     string  `json:"file"`
	Rules    []rule  `json:"rules"`
	Interval float64 `json:"interval"`
}

type rule struct {
	*alertingRule
	*recordingRule
}

func (r *rule) GetLabels() labels.Labels {
	if r.alertingRule != nil {
		return r.alertingRule.Labels
	}
	return r.recordingRule.Labels
}

// MarshalJSON implements the json.Marshaler interface for rule.
func (r *rule) MarshalJSON() ([]byte, error) {
	if r.alertingRule != nil {
		return json.Marshal(r.alertingRule)
	}
	return json.Marshal(r.recordingRule)
}

// UnmarshalJSON implements the json.Unmarshaler interface for rule.
func (r *rule) UnmarshalJSON(b []byte) error {
	var ruleType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &ruleType); err != nil {
		return err
	}
	switch ruleType.Type {
	case "alerting":
		var alertingr alertingRule
		if err := json.Unmarshal(b, &alertingr); err != nil {
			return err
		}
		r.alertingRule = &alertingr
	case "recording":
		var recordingr recordingRule
		if err := json.Unmarshal(b, &recordingr); err != nil {
			return err
		}
		r.recordingRule = &recordingr
	default:
		return fmt.Errorf("failed to unmarshal rule: unknown type %q", ruleType.Type)
	}

	return nil
}

type rulesData struct {
	RuleGroups []*ruleGroup `json:"groups,omitempty"`
	Alerts     []*alert     `json:"alerts,omitempty"`
}

type prometheusRulesResponse struct {
	Status    string    `json:"status"`
	Data      rulesData `json:"data"`
	Error     string    `json:"error"`
	ErrorType string    `json:"errorType"`
}

type lokiRule struct {
	Alert       string            `json:"alert,omitempty"`
	Record      string            `json:"record,omitempty"`
	Expr        string            `json:"expr,omitempty"`
	For         string            `json:"for,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

func (r *lokiRule) GetLabels() labels.Labels { return labels.FromMap(r.Labels) }

type lokiRuleGroup struct {
	Name     string     `json:"name"`
	Interval string     `json:"interval,omitempty"`
	Limit    int        `json:"limit,omitempty"`
	Rules    []lokiRule `json:"rules"`
}

type lokiRulesResponse = map[string][]lokiRuleGroup

func WithEnforceRulesLabelFilters(labelKeys map[string][]string) func(http.Handler) http.Handler {
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

			// If the authorization endpoint provides any matchers, ensure that the URL parameter value
			// matches an authorization matcher with the same URL parameter key.
			queryParams := r.URL.Query()
			for _, key := range keys {
				var (
					val     = queryParams.Get(key)
					matched = false
				)

				for _, matcher := range matchers {
					if matcher == nil {
						continue
					}

					if matcher.Name == key && matcher.Matches(val) {
						matched = true
						break
					}
				}

				if !matched {
					httperr.PrometheusAPIError(w, fmt.Sprintf("unauthorized access for URL parameter %q and value %q", key, val), http.StatusForbidden)

					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func newModifyResponse(logger log.Logger, labelKeys map[string][]string) func(*http.Response) error {
	return func(res *http.Response) error {
		tenant, ok := authentication.GetTenant(res.Request.Context())
		if !ok {
			return errUnknownTenantKey
		}

		keys, ok := labelKeys[tenant]
		if !ok {
			level.Debug(logger).Log("msg", "Skip applying rule label filters", "tenant", tenant)
			return nil
		}

		var (
			matchers    = extractMatchers(res.Request, keys)
			contentType = res.Header.Get("Content-Type")
		)

		data, ok := authorization.GetData(res.Request.Context())

		var matchersInfo AuthzResponseData
		if ok && data != "" {
			if err := json.Unmarshal([]byte(data), &matchersInfo); err != nil {
				return nil
			}
		}

		strictMode := len(matchersInfo.Matchers) != 0

		matcherStr := fmt.Sprintf("%s", matchers)
		level.Debug(logger).Log("msg", "filtering using matchers", "tenant", tenant, "matchers", matcherStr)

		body, err := io.ReadAll(res.Body)
		if err != nil {
			level.Error(logger).Log("msg", err)
			return err
		}
		res.Body.Close()

		b, err := filterRules(body, contentType, matchers, strictMode)
		if err != nil {
			level.Error(logger).Log("msg", err)
			return err
		}

		res.Body = io.NopCloser(bytes.NewReader(b))
		res.ContentLength = int64(len(b))

		return nil
	}
}

func extractMatchers(r *http.Request, l []string) map[string]string {
	queryParams := r.URL.Query()
	matchers := map[string]string{}
	for _, name := range l {
		value := queryParams.Get(name)
		if value != "" {
			matchers[name] = value
		}
	}

	return matchers
}

func filterRules(body []byte, contentType string, matchers map[string]string, strictMode bool) ([]byte, error) {
	switch contentType {
	case contentTypeApplicationJSON:
		var res prometheusRulesResponse
		err := json.Unmarshal(body, &res)
		if err != nil {
			return nil, err
		}

		return json.Marshal(filterPrometheusResponse(res, matchers, strictMode))

	case contentTypeApplicationYAML:
		var res lokiRulesResponse
		if err := yaml.Unmarshal(body, &res); err != nil {
			return nil, err
		}

		return yaml.Marshal(filterLokiRules(res, matchers, strictMode))

	default:
		return nil, errUnknownRulesContentType
	}
}

func filterPrometheusResponse(res prometheusRulesResponse, matchers map[string]string, strictEnforce bool) prometheusRulesResponse {
	if len(matchers) == 0 {
		if strictEnforce {
			res.Data = rulesData{}
		}

		return res
	}

	if len(res.Data.RuleGroups) > 0 {
		filtered := filterPrometheusRuleGroups(res.Data.RuleGroups, matchers)
		res.Data = rulesData{RuleGroups: filtered}
	}

	if len(res.Data.Alerts) > 0 {
		filtered := filterPrometheusAlerts(res.Data.Alerts, matchers)
		res.Data = rulesData{Alerts: filtered}
	}

	return res
}

type labeledRule interface {
	GetLabels() labels.Labels
}

func hasMatchingLabels(rule labeledRule, matchers map[string]string) bool {
	for key, value := range matchers {
		labels := rule.GetLabels().Map()
		val, ok := labels[key]
		if !ok || val != value {
			return false
		}
	}
	return true
}

func filterPrometheusRuleGroups(groups []*ruleGroup, matchers map[string]string) []*ruleGroup {
	var filtered []*ruleGroup

	for _, group := range groups {
		var filteredRules []rule
		for _, rule := range group.Rules {
			if hasMatchingLabels(&rule, matchers) {
				filteredRules = append(filteredRules, rule)
			}
		}

		if len(filteredRules) > 0 {
			group.Rules = filteredRules
			filtered = append(filtered, group)
		}
	}

	return filtered
}

func filterPrometheusAlerts(alerts []*alert, matchers map[string]string) []*alert {
	var filtered []*alert
	for _, alert := range alerts {
		if hasMatchingLabels(alert, matchers) {
			filtered = append(filtered, alert)
		}
	}

	return filtered
}

func filterLokiRules(res lokiRulesResponse, matchers map[string]string, strictEnforce bool) lokiRulesResponse {
	if len(matchers) == 0 {
		if strictEnforce {
			return nil
		}

		return res
	}

	filtered := lokiRulesResponse{}

	for name, groups := range res {
		var filteredGroups []lokiRuleGroup

		for _, group := range groups {
			var filteredRules []lokiRule
			for _, rule := range group.Rules {
				if hasMatchingLabels(&rule, matchers) {
					filteredRules = append(filteredRules, rule)
				}
			}

			if len(filteredRules) > 0 {
				group.Rules = filteredRules
				filteredGroups = append(filteredGroups, group)
			}
		}

		if len(filteredGroups) > 0 {
			filtered[name] = filteredGroups
		}
	}

	return filtered
}
