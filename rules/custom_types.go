package rules

import (
	"encoding/json"
)

func (rg *RuleGroup) UnmarshalJSON(data []byte) error {
	raw := struct {
		Interval string            `json:"interval"`
		Name     string            `json:"name"`
		Rules    []json.RawMessage `json:"rules"`
	}{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	rg.Interval = raw.Interval
	rg.Name = raw.Name
	rules := make([]interface{}, 0, len(raw.Rules))

	for i := range raw.Rules {
		rawRule := make(map[string]json.RawMessage)
		if err := json.Unmarshal(raw.Rules[i], &rawRule); err != nil {
			return err
		}

		switch _, ok := rawRule["alert"]; ok {
		case true:
			var ar AlertingRule
			if err := json.Unmarshal(raw.Rules[i], &ar); err != nil {
				return err
			}

			rules = append(rules, ar)
		case false:
			var rr RecordingRule
			if err := json.Unmarshal(raw.Rules[i], &rr); err != nil {
				return err
			}

			rules = append(rules, rr)
		}
	}

	if len(rules) != 0 {
		rg.Rules = rules
	}

	return nil
}
