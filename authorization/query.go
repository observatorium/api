package authorization

import (
	"net/url"
	"strings"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

func extractQuerySelectors(selectorLabels map[string]bool, values url.Values) (*SelectorsInfo, error) {
	query := values.Get("query")
	if query == "" {
		return emptySelectorsInfo, nil
	}

	selectors, hasWildcard, err := parseQueryNamespaces(selectorLabels, query)
	if err != nil {
		return nil, err
	}

	return &SelectorsInfo{
		Selectors:   selectors,
		HasWildcard: hasWildcard,
	}, nil
}

func parseQueryNamespaces(selectorLabels map[string]bool, query string) (map[string][]string, bool, error) {
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
				if _, ok := selectorLabels[m.Name]; !ok {
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
