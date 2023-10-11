package authorization

import (
	"fmt"
	"net/url"
	"strings"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

func extractLogStreamSelectors(selectorNames map[string]bool, values url.Values) (*SelectorsInfo, error) {
	query := values.Get("query")
	if query == "" {
		// If query is empty we will assume it's a possibly a metadata/rules request
		selectors, err := parseLogRulesSelectors(selectorNames, values)
		if err != nil {
			return nil, fmt.Errorf("error extracting selectors from parameters %#q: %w", values, err)
		}
	
		return &SelectorsInfo{
			Selectors:   selectors,
		}, nil
	}

	selectors, hasWildcard, err := parseLogStreamSelectors(selectorNames, query)
	if err != nil {
		return nil, fmt.Errorf("error extracting selectors from query %#q: %w", query, err)
	}

	return &SelectorsInfo{
		Selectors:   selectors,
		HasWildcard: hasWildcard,
	}, nil
}

func parseLogStreamSelectors(selectorNames map[string]bool, query string) (map[string][]string, bool, error) {
	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return nil, false, err
	}

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
	expr.Walk(func(expr interface{}) {
		switch le := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			for _, m := range le.Matchers() {
				if _, ok := selectorNames[m.Name]; !ok {
					continue
				}

				switch m.Type {
				case labels.MatchEqual:
					appendSelector(m.Name, m.Value)
				case labels.MatchRegexp:
					values := strings.Split(m.Value, "|")
					for _, v := range values {
						if strings.ContainsAny(v, ".+*") {
							hasWildcard = true
							continue
						}

						appendSelector(m.Name, v)
					}
				}
			}
		default:
			// Do nothing
		}
	})

	return selectors, hasWildcard, nil
}
