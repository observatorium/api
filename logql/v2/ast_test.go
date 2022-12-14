// nolint:testpackage,paralleltest,lll
package v2

import (
	"testing"

	"github.com/prometheus/prometheus/pkg/labels"
)

func Test_AstWalker_SimpleCountExpr(t *testing.T) {
	type tt struct {
		input string
		total int
	}

	tc := []tt{
		{
			input: "100 * 100",
			total: 3,
		}, {
			input: `{first="value"} |= "baz" |= ip("8.8.8.8")`,
			total: 2,
		},
	}
	for _, tc := range tc {
		tc := tc

		expr, err := ParseExpr(tc.input)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		total := 0

		expr.Walk(func(_ interface{}) {
			total++
		})

		if total != tc.total {
			t.Fatalf("got: %d, want: %d", total, tc.total)
		}
	}
}

func Test_AstWalker_AppendMatcher(t *testing.T) {
	type tt struct {
		input  string
		output string
	}

	l := []*labels.Matcher{
		{
			Type:  labels.MatchEqual,
			Name:  "second",
			Value: "next",
		},
	}

	tc := []tt{
		// log number expressions
		{
			input:  "100 * 100",
			output: "100 * 100",
		},
		{
			input:  "100 * -100",
			output: "100 * -100",
		},
		// log selector expressions
		{
			input:  `{first="value"}`,
			output: `{first="value", second="next"}`,
		},
		{
			input:  `{first="value"} |= "other" |= ip("8.8.8.8")`,
			output: `{first="value", second="next"} |= "other" |= ip("8.8.8.8")`,
		},
		{
			input:  `{ first = "value" }|logfmt|addr>=ip("1.1.1.1")`,
			output: `{first="value", second="next"} | logfmt | addr>=ip("1.1.1.1")`,
		},
		// log metric expressions
		{
			input:  `sum(rate({first="value"}[5m]))`,
			output: `sum(rate({first="value", second="next"}[5m]))`,
		},
		{
			input:  `max without (second) (count_over_time({first="value"}[5h]))`,
			output: `max without(second) (count_over_time({first="value", second="next"}[5h]))`,
		},
		// log binary expressions
		{
			input:  `sum(rate({first="value"}[5m])) / sum(rate({first="value"}[5m]))`,
			output: `sum(rate({first="value", second="next"}[5m])) / sum(rate({first="value", second="next"}[5m]))`,
		},
		{
			input: `sum by(job) (
							count_over_time({title="martian"} |= "level=error"[5m])
						/
							count_over_time({title="martian"}[5m])
						)  * 100`,
			output: `sum by(job) (count_over_time(({title="martian", second="next"} |= "level=error") [5m]) / count_over_time({title="martian", second="next"}[5m])) * 100`,
		},
		// multiline expressions
		{
			input: `avg(
					label_replace(
						count_over_time({first="value"}[5h]),
						"value",
						"$1$2",
						"first",
						"(.*).(.*)"
					)
				) by(second,first)`,
			output: `avg(label_replace(count_over_time({first="value", second="next"}[5h]),"value","$1$2","first","(.*).(.*)")) by(second,first)`,
		},
	}
	for _, tc := range tc {
		tc := tc

		expr, err := ParseExpr(tc.input)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		expr.Walk(func(e interface{}) {
			switch ex := e.(type) { //nolint:gocritic
			case *StreamMatcherExpr:
				ex.AppendMatchers(l)
			}
		})

		got := expr.String()
		if got != tc.output {
			t.Fatalf("\ngot:  %s\nwant: %s", got, tc.output)
		}
	}
}
