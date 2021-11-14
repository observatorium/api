package rules

import (
	"testing"

	"github.com/ghodss/yaml"
)

func TestRuleGroupUnmarshalJSON(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  []byte
		out  RuleGroup
		err  bool
	}{
		{
			name: "almost empty",
			raw:  []byte("{}"),
		},
		{
			name: "one recording rule",
			raw: []byte(`
name: foo
interval: 5s
rules:
- record: bar
  expr: vector(1)`),
			out: RuleGroup{
				Name:     "foo",
				Interval: "5s",
				Rules: []interface{}{
					RecordingRule{
						Record: "bar",
						Expr:   "vector(1)",
						Labels: RecordingRule_Labels{AdditionalProperties: make(map[string]string)},
					},
				},
			},
		},
		{
			name: "one alerting rule",
			raw: []byte(`
name: foo
interval: 5s
rules:
- alert: HighRequestLatency
  expr: job:request_latency_seconds:mean5m{job="myjob"} > 0.5
  for: 10m`),
			out: RuleGroup{
				Name:     "foo",
				Interval: "5s",
				Rules: []interface{}{
					AlertingRule{
						Alert:       "HighRequestLatency",
						Expr:        `job:request_latency_seconds:mean5m{job="myjob"} > 0.5`,
						For:         "10m",
						Annotations: AlertingRule_Annotations{AdditionalProperties: make(map[string]string)},
						Labels:      AlertingRule_Labels{AdditionalProperties: make(map[string]string)},
					},
				},
			},
		},
		{
			name: "one of each",
			raw: []byte(`
name: foo
interval: 5s
rules:
- record: bar
  expr: vector(1)
- alert: HighRequestLatency
  expr: job:request_latency_seconds:mean5m{job="myjob"} > 0.5
  for: 10m`),
			out: RuleGroup{
				Name:     "foo",
				Interval: "5s",
				Rules: []interface{}{
					RecordingRule{
						Record: "bar",
						Expr:   "vector(1)",
						Labels: RecordingRule_Labels{AdditionalProperties: make(map[string]string)},
					},
					AlertingRule{
						Alert:       "HighRequestLatency",
						Expr:        `job:request_latency_seconds:mean5m{job="myjob"} > 0.5`,
						For:         "10m",
						Annotations: AlertingRule_Annotations{AdditionalProperties: make(map[string]string)},
						Labels:      AlertingRule_Labels{AdditionalProperties: make(map[string]string)},
					},
				},
			},
		},
	} {
		tc := testCase
		t.Run(tc.name, func(t *testing.T) {
			var out RuleGroup
			if err := yaml.Unmarshal(tc.raw, &out); err != nil {
				if !tc.err {
					t.Fatalf("got unexpected error %v", err)
				}
			} else {
				if tc.err {
					t.Fatal("expected error")
				}
				if !ruleGroupsEqual(out, tc.out) {
					t.Errorf("expected %v; got %v", tc.out, out)
				}
			}
		})
	}
}

func ruleGroupsEqual(a, b RuleGroup) bool {
	if a.Interval != b.Interval {
		return false
	}

	if a.Name != b.Name {
		return false
	}

	if (a.Rules != nil) != (b.Rules != nil) {
		return false
	}

	if len(a.Rules) != len(b.Rules) {
		return false
	}

	for i := range a.Rules {
		ara, aok := a.Rules[i].(AlertingRule)
		bra, bok := b.Rules[i].(AlertingRule)

		if aok != bok {
			return false
		}

		if aok {
			if ara.Alert != bra.Alert {
				return false
			}

			if ara.Expr != bra.Expr {
				return false
			}

			if ara.For != bra.For {
				return false
			}

			if mapsEqual(ara.Annotations.AdditionalProperties, bra.Annotations.AdditionalProperties) {
				return false
			}

			if mapsEqual(ara.Labels.AdditionalProperties, bra.Labels.AdditionalProperties) {
				return false
			}

			continue
		}

		arr, aok := a.Rules[i].(RecordingRule)
		brr, bok := b.Rules[i].(RecordingRule)

		if aok != bok {
			return false
		}

		if aok {
			if arr.Expr != brr.Expr {
				return false
			}

			if arr.Record != brr.Record {
				return false
			}

			if mapsEqual(arr.Labels.AdditionalProperties, brr.Labels.AdditionalProperties) {
				return false
			}

			continue
		}
	}

	return true
}

func mapsEqual(a, b map[string]string) bool {
	if a == nil && b == nil {
		return true
	}

	if (a != nil) != (b != nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for k := range a {
		if a[k] != b[k] {
			return false
		}
	}

	return true
}
