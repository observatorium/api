package rules

func (t RuleGroup_Rules_Item) IsRecordingRule() bool {
	ar, err := t.AsRecordingRule()
	if err != nil {
		return false
	}

	return ar.Record != ""
}

func (t RuleGroup_Rules_Item) IsAlertingRule() bool {
	ar, err := t.AsAlertingRule()
	if err != nil {
		return false
	}

	return ar.Alert != ""
}
