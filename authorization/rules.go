package authorization

import (
	"fmt"
	"net/url"
	"strings"
)

var (
	rulesAbsolutePaths = map[string]bool{
		"/loki/api/v1/rule":  true,
		"/loki/api/v1/rules": true,
		"/api/prom/rules":    true,
	}

	rulesPathLabelValuesNewPrefix = "/loki/api/v1/rules/"
	rulesPathLabelValuesOldPrefix = "/api/prom/rules/"
)

func isRulesRequest(path string) bool {
	if absolutePath := rulesAbsolutePaths[path]; absolutePath {
		return true
	}

	if (strings.HasPrefix(path, rulesPathLabelValuesNewPrefix) || strings.HasPrefix(path, rulesPathLabelValuesOldPrefix)) {
		return true
	}

	return false
}

func extractLogRulesSelectors(selectorNames map[string]bool, values url.Values) (*SelectorsInfo, error) {
	selectors, hasWildcard, err := parseLogRulesSelectors(selectorNames, values)
	if err != nil {
		return nil, fmt.Errorf("error extracting selectors from query parameters %#q: %w", values, err)
	}

	return &SelectorsInfo{
		Selectors:   selectors,
		HasWildcard: hasWildcard,
	}, nil
}

func parseLogRulesSelectors(selectorNames map[string]bool, queryParameter url.Values) (map[string][]string, bool, error) {
	selectors := make(map[string][]string)
	appendSelector := func(selector, value string) {
		values, ok := selectors[selector]
		if !ok {
			values = make([]string, 0)
		}

		values = append(values, value)
		selectors[selector] = values
	}

	hasWildcard := false
	for selector := range selectorNames {
		values := queryParameter[selector]
		for _, value := range values {
			appendSelector(selector, value)
		}
	}

	return selectors, hasWildcard, nil
}
