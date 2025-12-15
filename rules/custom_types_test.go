package rules

import (
	"encoding/json"
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
				Rules: []RuleGroup_Rules_Item{
					func() RuleGroup_Rules_Item {
						r := &RuleGroup_Rules_Item{}
						_ = r.FromRecordingRule(RecordingRule{
							Record: "bar",
							Expr:   "vector(1)",
						})
						return *r
					}(),
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
				Rules: []RuleGroup_Rules_Item{
					func() RuleGroup_Rules_Item {
						r := &RuleGroup_Rules_Item{}
						_ = r.FromAlertingRule(AlertingRule{
							Alert: "HighRequestLatency",
							Expr:  `job:request_latency_seconds:mean5m{job="myjob"} > 0.5`,
							For:   "10m",
							//			Annotations: map[string]string{},
							//			Labels:      map[string]string{},
						})
						return *r
					}(),
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
				Rules: []RuleGroup_Rules_Item{
					func() RuleGroup_Rules_Item {
						r := &RuleGroup_Rules_Item{}
						_ = r.FromRecordingRule(RecordingRule{
							Record: "bar",
							Expr:   "vector(1)",
							Labels: map[string]string{},
						})
						return *r
					}(),
					func() RuleGroup_Rules_Item {
						r := &RuleGroup_Rules_Item{}
						_ = r.FromAlertingRule(AlertingRule{
							Alert:       "HighRequestLatency",
							Expr:        `job:request_latency_seconds:mean5m{job="myjob"} > 0.5`,
							For:         "10m",
							Annotations: map[string]string{},
							Labels:      map[string]string{},
						})
						return *r
					}(),
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
					t.Log(string(tc.raw))
					b, _ := json.Marshal(tc.out)
					t.Log(string(b))
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
		isa, isb := a.Rules[i].IsAlertingRule(), b.Rules[i].IsAlertingRule()
		if isa != isb {
			return false
		}

		if isa {
			ara, erra := a.Rules[i].AsAlertingRule()
			bra, errb := a.Rules[i].AsAlertingRule()
			if erra != nil || errb != nil {
				return false
			}

			if ara.Alert != bra.Alert {
				return false
			}

			if ara.Expr != bra.Expr {
				return false
			}

			if ara.For != bra.For {
				return false
			}

			if !mapsEqual(ara.Annotations, bra.Annotations) {
				return false
			}

			if !mapsEqual(ara.Labels, bra.Labels) {
				return false
			}

			continue
		}

		isa, isb = a.Rules[i].IsRecordingRule(), b.Rules[i].IsRecordingRule()
		if isa != isb {
			return false
		}

		if isa {
			arr, aerr := a.Rules[i].AsRecordingRule()
			brr, berr := b.Rules[i].AsRecordingRule()

			if (aerr == nil) != (berr == nil) {
				return false
			}
			if arr.Expr != brr.Expr {
				return false
			}

			if arr.Record != brr.Record {
				return false
			}

			if !mapsEqual(arr.Labels, brr.Labels) {
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
