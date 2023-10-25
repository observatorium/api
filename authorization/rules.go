package authorization

import (
	"net/url"
)

func parseLogRulesSelectors(selectorNames map[string]bool, queryParameter url.Values) map[string][]string {
	selectors := make(map[string][]string)
	appendSelector := func(selector, value string) {
		values, ok := selectors[selector]
		if !ok {
			values = make([]string, 0)
		}

		values = append(values, value)
		selectors[selector] = values
	}

	for selector := range selectorNames {
		values := queryParameter[selector]
		for _, value := range values {
			appendSelector(selector, value)
		}
	}

	return selectors
}
