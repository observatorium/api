package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/observatorium/api/authentication"
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
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			got := filterPrometheusResponse(tc.res, tc.matchers, tc.strictEnforce)

			wantJSON, err := json.MarshalIndent(tc.want, "", "  ")
			if err != nil {
				t.Errorf("failed to marshal expected JSON: %v", err)
			}

			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Errorf("failed to marshal actual JSON: %v", err)
			}

			if string(wantJSON) != string(gotJSON) {
				t.Errorf("\nwant: %s\ngot: %s", wantJSON, gotJSON)
			}
		})
	}
}

func TestFilterPrometheusAlertingRules(t *testing.T) {
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
					Alerts: []*alert{
						{Labels: labels.FromMap(map[string]string{"alertname": "alert-a"})},
					},
				},
			},
			want: prometheusRulesResponse{},
		},
		{
			desc: "without matchers returns original response",
			res: prometheusRulesResponse{
				Data: rulesData{
					Alerts: []*alert{
						{Labels: labels.FromMap(map[string]string{"alertname": "alert-a"})},
					},
				},
			},
			want: prometheusRulesResponse{
				Data: rulesData{
					Alerts: []*alert{
						{Labels: labels.FromMap(map[string]string{"alertname": "alert-a"})},
					},
				},
			},
		},
		{
			desc:     "only matching",
			matchers: map[string]string{"label": "value"},
			res: prometheusRulesResponse{
				Data: rulesData{
					Alerts: []*alert{
						{Labels: labels.FromMap(map[string]string{"label": "value"})},
						{Labels: labels.FromMap(map[string]string{"other": "not"})},
					},
				},
			},
			want: prometheusRulesResponse{
				Data: rulesData{
					Alerts: []*alert{
						{Labels: labels.FromMap(map[string]string{"label": "value"})},
					},
				},
			},
		},
		{
			desc:     "nothing matching",
			matchers: map[string]string{"label": "value"},
			res: prometheusRulesResponse{
				Data: rulesData{
					Alerts: []*alert{
						{Labels: labels.FromMap(map[string]string{"not": "other"})},
					},
				},
			},
			want: prometheusRulesResponse{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			got := filterPrometheusResponse(tc.res, tc.matchers, tc.strictEnforce)

			wantJSON, err := json.MarshalIndent(tc.want, "", "  ")
			if err != nil {
				t.Errorf("failed to marshal expected JSON: %v", err)
			}

			gotJSON, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Errorf("failed to marshal actual JSON: %v", err)
			}

			if string(wantJSON) != string(gotJSON) {
				t.Errorf("\nwant: %s\ngot: %s", wantJSON, gotJSON)
			}
		})
	}
}

func TestModifyResponse(t *testing.T) {
	l := log.NewNopLogger()
	lk := map[string][]string{
		"fake": {"namespace"},
	}

	rules, err := os.ReadFile("testdata/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	originanLen := int64(len(rules))

	filtered, err := os.ReadFile("testdata/rules-log-test-0.json")
	if err != nil {
		t.Fatal(err)
	}
	filteredLen := int64(len(filtered))

	headers := make(http.Header)
	headers.Add("Content-Type", "application/json")

	res := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(rules)),
		ContentLength: originanLen,
	}

	proxy := &httputil.ReverseProxy{
		Director:       func(r *http.Request) {},
		Transport:      staticResponseRoundTripper{res},
		ModifyResponse: newModifyResponseProm(l, lk),
	}

	r := chi.NewRouter()
	r.Handle("/rules/{tenant}", authentication.WithTenant(proxy))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest("GET", "/rules/fake?namespace=log-test-0", nil))

	result := rr.Result()
	if result.StatusCode != http.StatusOK {
		t.Errorf("Broken routing: %s", rr.Result().Status)
	}

	if result.ContentLength == originanLen || result.ContentLength != filteredLen {
		t.Errorf("failed to filter rules, original len: %d, want: %d, got: %d", originanLen, filteredLen, result.ContentLength)
	}
}

type staticResponseRoundTripper struct {
	res *http.Response
}

func (rt staticResponseRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.res.Request = r
	return rt.res, nil
}
