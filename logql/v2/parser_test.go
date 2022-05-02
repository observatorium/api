// nolint:exhaustivestruct,testpackage
package v2

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/pkg/labels"
)

//nolint:paralleltest,funlen
func TestParseExpr(t *testing.T) {
	type tt struct {
		input            string
		expr             Expr
		err              error
		doNotcheckString bool
	}

	tc := []tt{
		// log selector expressions
		{
			input: `{first="value"}`,
			expr: &StreamMatcherExpr{
				matchers: []*labels.Matcher{
					{
						Type:  labels.MatchEqual,
						Name:  "first",
						Value: "value",
					},
				},
			},
		},
		{
			input: `{first="value", value!="other"}`,
			expr: &StreamMatcherExpr{
				matchers: []*labels.Matcher{
					{
						Type:  labels.MatchEqual,
						Name:  "first",
						Value: "value",
					},
					{
						Type:  labels.MatchNotEqual,
						Name:  "value",
						Value: "other",
					},
				},
			},
		},
		// log query expressions with filter
		{
			input: `{first="value"} |= "other"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						stages: LogFiltersExpr{
							{
								filter: "|=",
								value:  "other",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{first="value"} |= "other" |= ip("8.8.8.8")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						stages: LogFiltersExpr{
							{
								filter: "|=",
								value:  "other",
							},
							{
								filter:   "|=",
								filterOp: "ip",
								value:    `8.8.8.8`,
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{ first = "value" }|logfmt|addr>=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "logfmt",
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "addr",
								aliasOp:  ">=",
								filterOp: "ip",
								value:    `1.1.1.1`,
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{ first = "value" }|logfmt|remote_addr=ip("10.0.0.0")|level="error"|addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "logfmt",
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "remote_addr",
								aliasOp:  "=",
								filterOp: "ip",
								value:    "10.0.0.0",
							},
						},
					},
					{
						stages: LogFiltersExpr{
							{
								filter:  "|",
								alias:   "level",
								aliasOp: "=",
								value:   "error",
							},
						},
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "addr",
								aliasOp:  "=",
								filterOp: "ip",
								value:    "1.1.1.1",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{first="value"} |= "other" |~ "loop" != "while" !~ "goto"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						stages: LogFiltersExpr{
							{
								filter: "|=",
								value:  "other",
							},
							{
								filter: "|~",
								value:  "loop",
							},
							{
								filter: "!=",
								value:  "while",
							},
							{
								filter: "!~",
								value:  "goto",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		// log query expressions with parsers
		{
			input: `{first="value"} | logfmt | addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "logfmt",
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "addr",
								aliasOp:  "=",
								filterOp: "ip",
								value:    "1.1.1.1",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{first="value"} | json | addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "json",
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "addr",
								aliasOp:  "=",
								filterOp: "ip",
								value:    "1.1.1.1",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{first="value"} | unpack | addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "unpack",
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "addr",
								aliasOp:  "=",
								filterOp: "ip",
								value:    "1.1.1.1",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{first="value"} | regexp "(.)*" | addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "regexp",
						matcher: &LogFormatExpr{
							sep: "",
							kv:  LogFormatValues{"": newLogFormatValue("(.)*", false)},
						},
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "addr",
								aliasOp:  "=",
								filterOp: "ip",
								value:    "1.1.1.1",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		{
			input: `{first="value"} | pattern "(.)*" | addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "pattern",
						matcher: &LogFormatExpr{
							sep: "",
							kv:  LogFormatValues{"": newLogFormatValue("(.)*", false)},
						},
					},
					{
						stages: LogFiltersExpr{
							{
								filter:   "|",
								alias:    "addr",
								aliasOp:  "=",
								filterOp: "ip",
								value:    "1.1.1.1",
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "first",
							Value: "value",
						},
					},
				},
			},
		},
		// log query expressions with format expressions
		{
			input: `{app="first"} |= "value" | json | line_format "loop{{ .first }}blop {{.status_code}}" | label_format first=value,status_code="blop{{.value}}"`, //nolint:lll
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						stages: LogFiltersExpr{
							{
								filter: "|=",
								value:  "value",
							},
						},
					},
					{
						parser: "json",
					},
					{
						parser: "line_format",
						matcher: &LogFormatExpr{
							sep: "",
							kv: LogFormatValues{
								"": newLogFormatValue("loop{{ .first }}blop {{.status_code}}", false),
							},
						},
					},
					{
						parser: "label_format",
						matcher: &LogFormatExpr{
							sep: ",",
							kv: LogFormatValues{
								"first":       newLogFormatValue("value", true),
								"status_code": newLogFormatValue("blop{{.value}}", false),
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "app",
							Value: "first",
						},
					},
				},
			},
		},
		// log metric expressions
		{
			input: `rate({first="value"}[1m])`,
			expr: &LogMetricExpr{
				metricOp: "rate",
				left: &LogRangeQueryExpr{
					rng: `[1m]`,
					left: &LogQueryExpr{
						left: &StreamMatcherExpr{
							matchers: []*labels.Matcher{
								{
									Type:  labels.MatchEqual,
									Name:  "first",
									Value: "value",
								},
							},
						},
					},
				},
			},
		},
		{
			input: `sum(rate({first="value"}[1m]))`,
			expr: &LogMetricExpr{
				metricOp: "sum",
				Expr: &LogMetricExpr{
					metricOp: "rate",
					left: &LogRangeQueryExpr{
						rng: `[1m]`,
						left: &LogQueryExpr{

							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "first",
										Value: "value",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			input: `count_over_time({first="value"}[24h] |= "error")`,
			expr: &LogMetricExpr{
				metricOp: `count_over_time`,
				left: &LogRangeQueryExpr{
					rng: `[24h]`,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							{
								stages: LogFiltersExpr{
									{
										filter: "|=",
										value:  "error",
									},
								},
							},
						},
						left: &StreamMatcherExpr{
							matchers: []*labels.Matcher{
								{
									Type:  labels.MatchEqual,
									Name:  "first",
									Value: "value",
								},
							},
						},
					},
				},
			},
		},
		{
			input: `count_over_time({first="value"} |= "error" [24h])`,
			expr: &LogMetricExpr{
				metricOp: `count_over_time`,
				left: &LogRangeQueryExpr{
					rng:     `[24h]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							{
								stages: LogFiltersExpr{
									{
										filter: "|=",
										value:  "error",
									},
								},
							},
						},
						left: &StreamMatcherExpr{
							matchers: []*labels.Matcher{
								{
									Type:  labels.MatchEqual,
									Name:  "first",
									Value: "value",
								},
							},
						},
					},
				},
			},
		},
		{
			input: `bytes_over_time(({first="value"} |= "other" |~ "loop" != "while" !~ "goto")[1m])`,
			expr: &LogMetricExpr{
				metricOp: "bytes_over_time",
				left: &LogRangeQueryExpr{
					rng:     `[1m]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							{
								stages: LogFiltersExpr{
									{
										filter: "|=",
										value:  "other",
									},
									{
										filter: "|~",
										value:  "loop",
									},
									{
										filter: "!=",
										value:  "while",
									},
									{
										filter: "!~",
										value:  "goto",
									},
								},
							},
						},
						left: &StreamMatcherExpr{
							matchers: []*labels.Matcher{
								{
									Type:  labels.MatchEqual,
									Name:  "first",
									Value: "value",
								},
							},
						},
					},
				},
			},
		},
		// metric expressions with groupings
		{
			input: `avg(count_over_time({first="value"}[10h])) by ()`,
			expr: &LogMetricExpr{
				metricOp: "avg",
				grouping: &grouping{without: false, groups: nil},
				Expr: &LogMetricExpr{
					metricOp: "count_over_time",
					left: &LogRangeQueryExpr{
						rng: "[10h]",
						left: &LogQueryExpr{
							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "first",
										Value: "value",
									},
								},
							},
						},
					},
				},
			},
		},
		// metric expressions with preamble
		{
			input: `topk(25,count_over_time({first="value"}[10h])) without(value)`,
			expr: &LogMetricExpr{
				metricOp: "topk",
				preamble: "25",
				grouping: &grouping{without: true, groups: []string{"value"}},
				Expr: &LogMetricExpr{
					metricOp: "count_over_time",
					left: &LogRangeQueryExpr{
						rng: "[10h]",
						left: &LogQueryExpr{
							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "first",
										Value: "value",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			input: `max without (value) (count_over_time({first="value"}[10h]))`,
			expr: &LogMetricExpr{
				metricOp: "max",
				grouping: &grouping{without: true, groups: []string{"value"}},
				Expr: &LogMetricExpr{
					metricOp: "count_over_time",
					left: &LogRangeQueryExpr{
						rng: "[10h]",
						left: &LogQueryExpr{
							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "first",
										Value: "value",
									},
								},
							},
						},
					},
				},
			},
			doNotcheckString: true,
		},
		// multi-line expressions
		{
			input: `avg(
					label_replace(
						count_over_time({first="value"}[10h]),
						"value",
						"$1$2",
						"first",
						"(.*).(.*)"
					)
				) by(value,first)`,
			expr: &LogMetricExpr{
				metricOp: "avg",
				grouping: &grouping{groups: []string{"value", "first"}},
				Expr: &LogMetricExpr{
					metricOp: "label_replace",
					params:   []string{"value", "$1$2", "first", "(.*).(.*)"},
					Expr: &LogMetricExpr{
						metricOp: "count_over_time",
						left: &LogRangeQueryExpr{
							rng: "[10h]",
							left: &LogQueryExpr{
								left: &StreamMatcherExpr{
									matchers: []*labels.Matcher{
										{
											Type:  labels.MatchEqual,
											Name:  "first",
											Value: "value",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			input: `
			label_replace(
				bytes_over_time(({first="value"} |= "other" |~ "loop" != "while" !~ "goto")[1m]),
				"blop",
				"$2",
				"value",
				"(.*):(.*)"
			)
			`,
			expr: &LogMetricExpr{
				metricOp: "label_replace",
				params: []string{
					"blop",
					"$2",
					"value",
					"(.*):(.*)",
				},
				Expr: &LogMetricExpr{
					metricOp: "bytes_over_time",
					left: &LogRangeQueryExpr{
						rng:     `[1m]`,
						rngLast: true,
						left: &LogQueryExpr{
							filter: LogPipelineExpr{
								{
									stages: LogFiltersExpr{
										{
											filter: "|=",
											value:  "other",
										},
										{
											filter: "|~",
											value:  "loop",
										},
										{
											filter: "!=",
											value:  "while",
										},
										{
											filter: "!~",
											value:  "goto",
										},
									},
								},
							},
							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "first",
										Value: "value",
									},
								},
							},
						},
					},
				},
			},
		},
		// log binary op expressions
		{
			input: `count_over_time({title="martian"} |= "level=error"[1m])	/ count_over_time({title="martian"}[1m])`,
			expr: LogBinaryOpExpr{
				Expr: &LogMetricExpr{
					metricOp: "count_over_time",
					left: &LogRangeQueryExpr{
						rng:     `[1m]`,
						rngLast: true,
						left: &LogQueryExpr{
							filter: LogPipelineExpr{
								{
									stages: LogFiltersExpr{
										{
											filter: "|=",
											value:  "level=error",
										},
									},
								},
							},
							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "title",
										Value: "martian",
									},
								},
							},
						},
					},
				},
				op:       "/",
				modifier: BinaryOpOptions{},
				right: &LogMetricExpr{
					metricOp: "count_over_time",
					left: &LogRangeQueryExpr{
						rng:     `[1m]`,
						rngLast: false,
						left: &LogQueryExpr{
							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "title",
										Value: "martian",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			input: `sum by (job) (
							count_over_time({title="martian"} |= "level=error"[1m])
						/
							bytes_over_time({title="martian"}[1m])
						)  * 100`,
			expr: LogBinaryOpExpr{
				Expr: &LogMetricExpr{
					metricOp: "sum",
					grouping: &grouping{groups: []string{"job"}},
					Expr: LogBinaryOpExpr{
						Expr: &LogMetricExpr{
							metricOp: "count_over_time",
							left: &LogRangeQueryExpr{
								rng:     `[1m]`,
								rngLast: true,
								left: &LogQueryExpr{
									filter: LogPipelineExpr{
										{
											stages: LogFiltersExpr{
												{
													filter: "|=",
													value:  "level=error",
												},
											},
										},
									},
									left: &StreamMatcherExpr{
										matchers: []*labels.Matcher{
											{
												Type:  labels.MatchEqual,
												Name:  "title",
												Value: "martian",
											},
										},
									},
								},
							},
						},
						op:       "/",
						modifier: BinaryOpOptions{},
						right: &LogMetricExpr{
							metricOp: "bytes_over_time",
							left: &LogRangeQueryExpr{
								rng:     `[1m]`,
								rngLast: false,
								left: &LogQueryExpr{
									left: &StreamMatcherExpr{
										matchers: []*labels.Matcher{
											{
												Type:  labels.MatchEqual,
												Name:  "title",
												Value: "martian",
											},
										},
									},
								},
							},
						},
					},
				},
				op:    "*",
				right: LogNumberExpr{value: 100},
			},
		},
		{
			input: `
					sum(count_over_time({first="value"}[1m])) by (first) +
					sum(bytes_over_time({first="value"}[1m])) by (first) /
					sum(absent_over_time({first="value"}[1m])) by (first)
					`,
			expr: LogBinaryOpExpr{
				Expr: &LogMetricExpr{
					metricOp: "sum",
					grouping: &grouping{groups: []string{"first"}},
					Expr: &LogMetricExpr{
						metricOp: "count_over_time",
						left: &LogRangeQueryExpr{
							rng: "[1m]",
							left: &LogQueryExpr{
								left: &StreamMatcherExpr{
									matchers: []*labels.Matcher{
										{
											Type:  labels.MatchEqual,
											Name:  "first",
											Value: "value",
										},
									},
								},
							},
						},
					},
				},
				op: "+",
				right: LogBinaryOpExpr{
					Expr: &LogMetricExpr{
						metricOp: "sum",
						grouping: &grouping{groups: []string{"first"}},
						Expr: &LogMetricExpr{
							metricOp: "bytes_over_time",
							left: &LogRangeQueryExpr{
								rng: "[1m]",
								left: &LogQueryExpr{
									left: &StreamMatcherExpr{
										matchers: []*labels.Matcher{
											{
												Type:  labels.MatchEqual,
												Name:  "first",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
					op: "/",
					right: &LogMetricExpr{
						metricOp: "sum",
						grouping: &grouping{groups: []string{"first"}},
						Expr: &LogMetricExpr{
							metricOp: "absent_over_time",
							left: &LogRangeQueryExpr{
								rng: "[1m]",
								left: &LogQueryExpr{
									left: &StreamMatcherExpr{
										matchers: []*labels.Matcher{
											{
												Type:  labels.MatchEqual,
												Name:  "first",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		// Log Number Expressions
		{
			input: "100 * -100",
			expr: LogBinaryOpExpr{
				Expr:  LogNumberExpr{value: 100},
				op:    "*",
				right: LogNumberExpr{value: 100, isNeg: true},
			},
		},
		{
			input: "100^100",
			expr: LogBinaryOpExpr{
				Expr:  LogNumberExpr{value: 100},
				op:    "^",
				right: LogNumberExpr{value: 100},
			},
		},
		{
			input: "100 > 100",
			expr: LogBinaryOpExpr{
				Expr:  LogNumberExpr{value: 100},
				op:    ">",
				right: LogNumberExpr{value: 100},
			},
		},
		// parse unwrap expression with a label filter
		{
			input: `rate({first="value"} | unwrap value [30s])`,
			expr: &LogMetricExpr{
				metricOp: "rate",
				left: &LogRangeQueryExpr{
					rng:     `[30s]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							{
								parser: "unwrap",
								matcher: &LogFormatExpr{
									sep: "",
									kv:  LogFormatValues{"": newLogFormatValue("value", true)},
								},
							},
						},
						left: &StreamMatcherExpr{
							matchers: []*labels.Matcher{
								{
									Type:  labels.MatchEqual,
									Name:  "first",
									Value: "value",
								},
							},
						},
					},
				},
			},
		},
		// parse unwrap expression of type bytes()/duration()/duration_seconds()
		{
			input: `sum_over_time({first="value"} | unwrap bytes(value) [5m])`,
			expr: &LogMetricExpr{
				metricOp: "sum_over_time",
				left: &LogRangeQueryExpr{
					rng:     `[5m]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							{
								parser: "unwrap",
								matcher: &LogFormatExpr{
									sep:       "",
									kv:        LogFormatValues{"": newLogFormatValue("value", true)},
									operation: "bytes",
								},
							},
						},
						left: &StreamMatcherExpr{
							matchers: []*labels.Matcher{
								{
									Type:  labels.MatchEqual,
									Name:  "first",
									Value: "value",
								},
							},
						},
					},
				},
			},
		},
		// log query expressions with format expressions and line function
		{
			input: `{app="first"} | line_format "{{ __line__ }} bar {{.status_code}}" | label_format status_code="401"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					{
						parser: "line_format",
						matcher: &LogFormatExpr{
							sep: "",
							kv: LogFormatValues{
								"": newLogFormatValue("{{ __line__ }} bar {{.status_code}}", false),
							},
						},
					},
					{
						parser: "label_format",
						matcher: &LogFormatExpr{
							sep: "",
							kv: LogFormatValues{
								"status_code": newLogFormatValue("401", false),
							},
						},
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "app",
							Value: "first",
						},
					},
				},
			},
		},
		// parse offset expression
		{
			input: `max_over_time({first="value"} | unwrap value [5m] offset 5m)`,
			expr: &LogMetricExpr{
				metricOp: "max_over_time",
				offset:   5 * time.Minute,
				left: &LogRangeQueryExpr{
					rng:     `[5m]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							{
								parser: "unwrap",
								matcher: &LogFormatExpr{
									sep: "",
									kv:  LogFormatValues{"": newLogFormatValue("value", true)},
								},
							},
						},
						left: &StreamMatcherExpr{
							matchers: []*labels.Matcher{
								{
									Type:  labels.MatchEqual,
									Name:  "first",
									Value: "value",
								},
							},
						},
					},
				},
			},
		},
		// parse offset expression with double grouping
		{
			input: `sum without (value) (quantile_over_time(0.98,{first="value"} | unwrap value [5m] offset 5m) by (namespace))`,
			expr: &LogMetricExpr{
				metricOp: "sum",
				grouping: &grouping{without: true, groups: []string{"value"}},
				Expr: &LogMetricExpr{
					metricOp: "quantile_over_time",
					preamble: "0.98",
					grouping: &grouping{without: false, groups: []string{"namespace"}},
					offset:   5 * time.Minute,
					left: &LogRangeQueryExpr{
						rng:     `[5m]`,
						rngLast: true,
						left: &LogQueryExpr{
							filter: LogPipelineExpr{
								{
									parser: "unwrap",
									matcher: &LogFormatExpr{
										sep: "",
										kv:  LogFormatValues{"": newLogFormatValue("value", true)},
									},
								},
							},
							left: &StreamMatcherExpr{
								matchers: []*labels.Matcher{
									{
										Type:  labels.MatchEqual,
										Name:  "first",
										Value: "value",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tc := range tc { //nolint:paralleltest
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			expr, err := ParseExpr(tc.input)

			if !errors.Is(tc.err, err) {
				t.Fatalf("unexpected err: %s", err)
			}

			if !reflect.DeepEqual(tc.expr, expr) {
				t.Fatalf("\ngot:  %#v\nwant: %#v", expr, tc.expr)
			}

			if !tc.doNotcheckString {
				if tc.expr.String() != expr.String() {
					t.Fatalf("\ngot: %s\nwant: %s", expr.String(), trimInput(tc.input))
				}
			}
		})
	}
}

func trimInput(s string) string {
	if s == "" {
		return s
	}

	s = strings.ReplaceAll(s, "by ()", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")

	return strings.TrimSpace(s)
}
