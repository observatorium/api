package authorization

import (
	"errors"
	"net/url"
	"strings"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

var (
	errWildcardRegexp = errors.New("regular expression with wildcards found")
)

func extractQueryNamespaces(namespaceLabels map[string]bool, values url.Values) ([]string, error) {
	query := values.Get("query")
	if query == "" {
		return []string{}, nil
	}

	namespaces, err := parseQueryNamespaces(namespaceLabels, query)
	if err != nil {
		return nil, err
	}

	return namespaces, nil
}

func parseQueryNamespaces(namespaceLabels map[string]bool, query string) ([]string, error) {
	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return nil, err
	}

	namespaces := []string{}
	failWildcard := false
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
							failWildcard = true
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

	if failWildcard {
		return nil, errWildcardRegexp
	}

	return namespaces, nil
}
