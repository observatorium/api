package authentication

import (
	"errors"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

const (
	namespaceMatcherKey = "kubernetes_namespace_name"
)

func parseQueryNamespaces(query string) ([]string, error) {
	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return nil, err
	}

	namespaces := []string{}
	expr.Walk(func(expr interface{}) {
		switch le := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			for _, m := range le.Matchers() {
				if m.Type != labels.MatchEqual {
					continue
				}

				if m.Name != namespaceMatcherKey {
					continue
				}

				namespaces = append(namespaces, m.Value)
			}
		default:
			// Do nothing
		}
	})

	if len(namespaces) == 0 {
		return nil, errors.New("no namespaces found")
	}

	return namespaces, nil
}
