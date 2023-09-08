package authorization

import (
	"net/url"
	"strings"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

func extractQueryNamespaces(namespaceLabels map[string]bool, values url.Values) (*NamespaceInfo, error) {
	query := values.Get("query")
	if query == "" {
		return emptyNamespaceInfo, nil
	}

	namespaces, hasWildcard, err := parseQueryNamespaces(namespaceLabels, query)
	if err != nil {
		return nil, err
	}

	return &NamespaceInfo{
		Namespaces:  namespaces,
		HasWildcard: hasWildcard,
	}, nil
}

func parseQueryNamespaces(namespaceLabels map[string]bool, query string) ([]string, bool, error) {
	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return nil, false, err
	}

	namespaces := []string{}
	hasWildcard := false
	expr.Walk(func(expr interface{}) {
		switch le := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			for _, m := range le.Matchers() {
				if _, ok := namespaceLabels[m.Name]; !ok {
					continue
				}

				switch m.Type {
				case labels.MatchEqual:
					namespaces = append(namespaces, m.Value)
				case labels.MatchRegexp:
					values := strings.Split(m.Value, "|")
					for _, v := range values {
						if strings.ContainsAny(v, ".+*") {
							hasWildcard = true
							continue
						}

						namespaces = append(namespaces, v)
					}
				}

				if m.Type != labels.MatchEqual {
					continue
				}

			}
		default:
			// Do nothing
		}
	})

	return namespaces, hasWildcard, nil
}
