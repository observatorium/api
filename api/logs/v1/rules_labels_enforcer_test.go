package http

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/prometheus/prometheus/model/labels"
)

func TestFilterRules_WithPrometheusAPIRulesResponseBody(t *testing.T) {
	contentType := "application/json"

	body, err := os.ReadFile("testdata/rules.json")
	if err != nil {
		t.Fatal(err)
	}

	matchers := map[string]string{
		"namespace": "log-test-0",
	}

	b, err := filterRules(body, contentType, matchers, true)
	if err != nil {
		t.Fatal(err)
	}

	var got prometheusRulesResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	for _, group := range got.Data.RuleGroups {
		for _, rule := range group.Rules {
			if val := rule.GetLabels().Get("namespace"); val != "log-test-0" {
				t.Errorf("invalid rule for label: %s and value: %s", "namespace", val)
			}
		}
	}
}

func TestFilterRules_WithPrometheusAPIAlertsResponseBody(t *testing.T) {
	contentType := "application/json"

	body, err := os.ReadFile("testdata/alerts.json")
	if err != nil {
		t.Fatal(err)
	}

	matchers := map[string]string{
		"namespace": "log-test-0",
	}

	b, err := filterRules(body, contentType, matchers, true)
	if err != nil {
		t.Fatal(err)
	}

	var got prometheusRulesResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	for _, alert := range got.Data.Alerts {
		if val := alert.Labels.Get("namespace"); val != "log-test-0" {
			t.Errorf("invalid rule for label: %s and value: %s", "namespace", val)
		}
	}
}

func TestFilterRules_WithPrometheusAPIResponseBody_ReturnNothingOnParseError(t *testing.T) {
	contentType := "application/json"
	body := []byte(`{`)
	matchers := map[string]string{
		"key": "value",
	}

	b, err := filterRules(body, contentType, matchers, true)
	if err == nil {
		t.Error("missing parse error")
	}

	if b != nil {
		t.Errorf("want nil, got: %s", b)
	}
}

func TestFilterRules_WithLokiAPIResponseBody(t *testing.T) {
	contentType := "application/yaml"

	body, err := os.ReadFile("testdata/rules.yaml")
	if err != nil {
		t.Fatal(err)
	}

	matchers := map[string]string{
		"namespace": "log-test-0",
	}

	b, err := filterRules(body, contentType, matchers, true)
	if err != nil {
		t.Error(err)
	}

	var got lokiRulesResponse
	if err := yaml.Unmarshal(b, &got); err != nil {
		t.Error(err)
	}

	for _, groups := range got {
		for _, group := range groups {
			for _, rule := range group.Rules {
				if val := rule.Labels["namespace"]; val != "log-test-0" {
					t.Errorf("invalid rule for label: %s and value: %s", "namespace", val)
				}
			}
		}
	}
}

func TestFilterRules_WithokiAPIResponseBody_ReturnNothingOnParseError(t *testing.T) {
	contentType := "application/yaml"
	body := []byte(`invalid`)
	matchers := map[string]string{
		"key": "value",
	}

	b, err := filterRules(body, contentType, matchers, true)
	if err == nil {
		t.Error("missing parse error")
	}

	if b != nil {
		t.Errorf("want nil, got: %s", b)
	}
}

func TestFilterRules_WithUnknownContentType_ReturnsError(t *testing.T) {
	contentType := "invalid/content"

	var (
		body     []byte
		matchers map[string]string
	)

	b, err := filterRules(body, contentType, matchers, true)
	if !errors.Is(err, errUnknownRulesContentType) {
		t.Errorf("want %s, got: %s", errUnknownRulesContentType, err)
	}

	if b != nil {
		t.Errorf("want nil, got: %s", b)
	}
}

func TestFilterPrometheusRules(t *testing.T) {
	tt := []struct {
		desc          string
		matchers      map[string]string
		strictEnforce bool
		res           prometheusRulesResponse
		want          prometheusRulesResponse
	}{
		{
			desc:          "without matchers returns empty",
			strictEnforce: true,
			res: prometheusRulesResponse{
				Data: rulesData{
					RuleGroups: []*ruleGroup{
						{Name: "group-a"},
					},
				},
			},
			want: prometheusRulesResponse{},
		},
		{
			desc: "without matchers returns original response",
			res: prometheusRulesResponse{
				Data: rulesData{
					RuleGroups: []*ruleGroup{
						{Name: "group-a"},
					},
				},
			},
			want: prometheusRulesResponse{
				Data: rulesData{
					RuleGroups: []*ruleGroup{
						{Name: "group-a"},
					},
				},
			},
		},
		{
			desc:     "only matching",
			matchers: map[string]string{"label": "value"},
			res: prometheusRulesResponse{
				Data: rulesData{
					RuleGroups: []*ruleGroup{
						{
							Name: "group-a",
							Rules: []rule{
								{
									alertingRule: &alertingRule{
										Labels: labels.FromMap(map[string]string{"label": "value"}),
									},
								},
								{
									alertingRule: &alertingRule{
										Labels: labels.FromMap(map[string]string{"other": "not"}),
									},
								},
							},
						},
					},
				},
			},
			want: prometheusRulesResponse{
				Data: rulesData{
					RuleGroups: []*ruleGroup{
						{
							Name: "group-a",
							Rules: []rule{
								{
									alertingRule: &alertingRule{
										Labels: labels.FromMap(map[string]string{"label": "value"}),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc:     "nothing matching",
			matchers: map[string]string{"label": "value"},
			res: prometheusRulesResponse{
				Data: rulesData{
					RuleGroups: []*ruleGroup{
						{
							Name: "group-a",
							Rules: []rule{
								{
									alertingRule: &alertingRule{
										Labels: labels.FromMap(map[string]string{"not": "other"}),
									},
								},
							},
						},
					},
				},
			},
			want: prometheusRulesResponse{},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			got := filterPrometheusResponse(tc.res, tc.matchers, tc.strictEnforce)

			wantJSON, err := json.MarshalIndent(tc.want, "", "  ")
			if err != nil {
				t.Errorf(err.Error())
			}

			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Errorf(err.Error())
			}

			if string(wantJSON) != string(gotJSON) {
				t.Errorf("\nwant: %s\ngot: %s", wantJSON, gotJSON)
			}
		})
	}
}

func TestFilterLokiRules(t *testing.T) {
	tt := []struct {
		desc          string
		matchers      map[string]string
		strictEnforce bool
		res           lokiRulesResponse
		want          lokiRulesResponse
	}{
		{
			desc:          "without matchers returns empty",
			strictEnforce: true,
			res: lokiRulesResponse{
				"ns-1": []lokiRuleGroup{
					{Name: "group-a"},
				},
				"ns-2": []lokiRuleGroup{
					{Name: "group-b"},
				},
			},
		},
		{
			desc: "without matchers returns original response",
			res: lokiRulesResponse{
				"ns-1": []lokiRuleGroup{
					{Name: "group-a"},
				},
				"ns-2": []lokiRuleGroup{
					{Name: "group-b"},
				},
			},
			want: lokiRulesResponse{
				"ns-1": []lokiRuleGroup{
					{Name: "group-a"},
				},
				"ns-2": []lokiRuleGroup{
					{Name: "group-b"},
				},
			},
		},
		{
			desc:     "only matching",
			matchers: map[string]string{"label": "value"},
			res: lokiRulesResponse{
				"ns-1": []lokiRuleGroup{
					{
						Name: "group-a",
						Rules: []lokiRule{
							{
								Alert:  "group-a-alert-1",
								Labels: map[string]string{"label": "value"},
							},
							{
								Alert:  "group-a-alert-2",
								Labels: map[string]string{"other": "not"},
							},
						},
					},
				},
				"ns-2": []lokiRuleGroup{
					{
						Name: "group-b",
						Rules: []lokiRule{
							{
								Alert:  "group-b-alert-1",
								Labels: map[string]string{"label": "value"},
							},
							{
								Alert:  "group-b-alert-2",
								Labels: map[string]string{"other": "not"},
							},
						},
					},
				},
			},
			want: lokiRulesResponse{
				"ns-1": []lokiRuleGroup{
					{
						Name: "group-a",
						Rules: []lokiRule{
							{
								Alert:  "group-a-alert-1",
								Labels: map[string]string{"label": "value"},
							},
						},
					},
				},
				"ns-2": []lokiRuleGroup{
					{
						Name: "group-b",
						Rules: []lokiRule{
							{
								Alert:  "group-b-alert-1",
								Labels: map[string]string{"label": "value"},
							},
						},
					},
				},
			},
		},
		{
			desc:     "nothing matching",
			matchers: map[string]string{"label": "value"},
			res: lokiRulesResponse{
				"ns-1": []lokiRuleGroup{
					{
						Name: "group-a",
						Rules: []lokiRule{
							{
								Alert:  "group-a-alert",
								Labels: map[string]string{"other": "not"},
							},
						},
					},
				},
				"ns-2": []lokiRuleGroup{
					{
						Name: "group-b",
						Rules: []lokiRule{
							{
								Alert:  "group-b-alert",
								Labels: map[string]string{"other": "not"},
							},
						},
					},
				},
			},
			want: lokiRulesResponse{},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			got := filterLokiRules(tc.res, tc.matchers, tc.strictEnforce)

			wantJSON, err := json.MarshalIndent(tc.want, "", "  ")
			if err != nil {
				t.Errorf(err.Error())
			}

			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Errorf(err.Error())
			}

			if string(wantJSON) != string(gotJSON) {
				t.Errorf("\nwant: %s\ngot: %s", wantJSON, gotJSON)
			}
		})
	}
}
