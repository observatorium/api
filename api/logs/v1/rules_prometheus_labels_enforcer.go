package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/authorization"
	"github.com/prometheus/prometheus/model/labels"
)

const contentTypeApplicationJSON = "application/json"

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
	State          string        `json:"state"`
	Name           string        `json:"name"`
	Query          string        `json:"query"`
	Duration       float64       `json:"duration"`
	Labels         labels.Labels `json:"labels"`
	Annotations    labels.Labels `json:"annotations"`
	Alerts         []*alert      `json:"alerts"`
	Health         string        `json:"health"`
	LastError      string        `json:"lastError"`
	LastEvaluation string        `json:"lastEvaluation"`
	EvaluationTime float64       `json:"evaluationTime"`
	// Type of an alertingRule is always "alerting".
	Type string `json:"type"`
}

type recordingRule struct {
	Name           string        `json:"name"`
	Query          string        `json:"query"`
	Labels         labels.Labels `json:"labels"`
	Health         string        `json:"health"`
	LastError      string        `json:"lastError"`
	LastEvaluation string        `json:"lastEvaluation"`
	EvaluationTime float64       `json:"evaluationTime"`
	// Type of a recordingRule is always "recording".
	Type string `json:"type"`
}

type ruleGroup struct {
	Name           string  `json:"name"`
	File           string  `json:"file"`
	Rules          []rule  `json:"rules"`
	Interval       float64 `json:"interval"`
	LastEvaluation string  `json:"lastEvaluation"`
	EvaluationTime float64 `json:"evaluationTime"`
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

func newModifyResponseProm(logger log.Logger, labelKeys map[string][]string) func(*http.Response) error {
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
		res.Header.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))

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
