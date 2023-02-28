// nolint:exhaustivestruct,testpackage
package v2

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
)

//nolint:paralleltest,funlen
func TestParseExpr(t *testing.T) {
	type tt struct {
		input string
		expr  Expr
		err   error
	}

	tc := []tt{
		// log selector expressions
		{
			input: `{first="value"}`,
			expr: &LogQueryExpr{left: &StreamMatcherExpr{
				matchers: []*labels.Matcher{
					{
						Type:  labels.MatchEqual,
						Name:  "first",
						Value: "value",
					},
				},
			}},
		},
		{
			input: `{first="value", value!="other"}`,
			expr: &LogQueryExpr{left: &StreamMatcherExpr{
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
			}},
		},
		// log query expressions with filter
		{
			input: `{first="value"} |= "other"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogFilterExpr{
						filter: "|=",
						value:  "other",
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
					&LogFilterExpr{
						filter: "|=",
						value:  "other",
					},
					&LogFilterExpr{
						filter:   "|=",
						filterOp: "ip",
						value:    `8.8.8.8`,
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
			input: `{first="value"} | logfmt | addr>=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "logfmt",
					},
					&LogLabelFilterExpr{
						labelName:    "addr",
						comparisonOp: ">=",
						filterOp:     "ip",
						labelValue:   "1.1.1.1",
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
			input: `{first="value"} | logfmt | remote_addr=ip("10.0.0.0") | level="error" | addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "logfmt",
					},
					&LogLabelFilterExpr{
						labelName:    "remote_addr",
						comparisonOp: "=",
						filterOp:     "ip",
						labelValue:   "10.0.0.0",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=",
						labelValue:   "error",
					},
					&LogLabelFilterExpr{
						labelName:    "addr",
						comparisonOp: "=",
						filterOp:     "ip",
						labelValue:   "1.1.1.1",
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
					&LogFilterExpr{
						filter: "|=",
						value:  "other",
					},
					&LogFilterExpr{
						filter: "|~",
						value:  "loop",
					},
					&LogFilterExpr{
						filter: "!=",
						value:  "while",
					},
					&LogFilterExpr{
						filter: "!~",
						value:  "goto",
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
					&LogParserExpr{
						parser: "logfmt",
					},
					&LogLabelFilterExpr{
						labelName:    "addr",
						comparisonOp: "=",
						filterOp:     "ip",
						labelValue:   "1.1.1.1",
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
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "addr",
						comparisonOp: "=",
						filterOp:     "ip",
						labelValue:   "1.1.1.1",
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
			input: `{first="value"} | json | level=~"info|notice"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=~",
						labelValue:   "info|notice",
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
			input: `{first="value"} | json | level="info" and level="notice" and level="information"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=",
						labelValue:   "info",
						right: []*LogLabelFilterExpr{
							{
								labelName:    "level",
								comparisonOp: "=",
								labelValue:   "notice",
								isNested:     true,
								chainOp:      "and",
							},
							{
								labelName:    "level",
								comparisonOp: "=",
								labelValue:   "information",
								isNested:     true,
								chainOp:      "and",
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
			input: `{first="value"} | json | level="info" and level="notice"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=",
						labelValue:   "info",
						right: []*LogLabelFilterExpr{
							{
								labelName:    "level",
								comparisonOp: "=",
								labelValue:   "notice",
								isNested:     true,
								chainOp:      "and",
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
			input: `{first="value"} | json | level="info" or level="notice" | other="info" and other="notice"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=",
						labelValue:   "info",
						right: []*LogLabelFilterExpr{
							{
								labelName:    "level",
								comparisonOp: "=",
								labelValue:   "notice",
								isNested:     true,

								chainOp: "or",
							},
						},
					},
					&LogLabelFilterExpr{
						labelName:    "other",
						comparisonOp: "=",
						labelValue:   "info",
						right: []*LogLabelFilterExpr{
							{
								labelName:    "other",
								comparisonOp: "=",
								labelValue:   "notice",
								isNested:     true,
								chainOp:      "and",
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
			input: `{first="value"} | json | level="info" or level="notice"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=",
						labelValue:   "info",
						right: []*LogLabelFilterExpr{
							{
								labelName:    "level",
								comparisonOp: "=",
								labelValue:   "notice",
								isNested:     true,
								chainOp:      "or",
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
			input: `{first="value"} | json | level="info", level="notice"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=",
						labelValue:   "info",
						right: []*LogLabelFilterExpr{
							{
								labelName:    "level",
								comparisonOp: "=",
								labelValue:   "notice",
								isNested:     true,
								chainOp:      ",",
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
					&LogParserExpr{
						parser: "unpack",
					},
					&LogLabelFilterExpr{
						labelName:    "addr",
						comparisonOp: "=",
						filterOp:     "ip",
						labelValue:   "1.1.1.1",
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
					&LogParserExpr{
						parser:     "regexp",
						identifier: "(.)*",
					},
					&LogLabelFilterExpr{
						labelName:    "addr",
						comparisonOp: "=",
						filterOp:     "ip",
						labelValue:   "1.1.1.1",
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
			input: `{log_type="application"} | json | pattern ` + "`" + `<_>:"<mytimestamp>",<_>` + "`",
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogParserExpr{
						parser:     "pattern",
						identifier: `<_>:"<mytimestamp>",<_>`,
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "log_type",
							Value: "application",
						},
					},
				},
			},
		},
		{
			input: `{kubernetes_namespace_name="log-test-0"} | json | level=~"critical|emerg|fatal|alert|crit|error|err|eror"`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser: "json",
					},
					&LogLabelFilterExpr{
						labelName:    "level",
						comparisonOp: "=~",
						labelValue:   "critical|emerg|fatal|alert|crit|error|err|eror",
					},
				},
				left: &StreamMatcherExpr{
					matchers: []*labels.Matcher{
						{
							Type:  labels.MatchEqual,
							Name:  "kubernetes_namespace_name",
							Value: "log-test-0",
						},
					},
				},
			},
		},
		{
			input: `{first="value"} | pattern "(.)*" | addr=ip("1.1.1.1")`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogParserExpr{
						parser:     "pattern",
						identifier: "(.)*",
					},
					&LogLabelFilterExpr{
						labelName:    "addr",
						comparisonOp: "=",
						filterOp:     "ip",
						labelValue:   "1.1.1.1",
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
					&LogFilterExpr{
						filter: "|=",
						value:  "value",
					},
					&LogParserExpr{
						parser: "json",
					},
					&LogParserExpr{
						parser:     "line_format",
						identifier: "loop{{ .first }}blop {{.status_code}}",
					},
					&LogFormatExpr{
						sep: ",",
						kv: LogFormatValues{
							"first":       LogFormatValue{Value: "value", IsIdentifier: true},
							"status_code": LogFormatValue{Value: "blop{{.value}}"},
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
			input: `rate_counter({first="value"}[1m])`,
			expr: &LogMetricExpr{
				metricOp: "rate_counter",
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
							&LogFilterExpr{
								filter: "|=",
								value:  "error",
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
			input: `count_over_time(({first="value"} |= "error") [24h])`,
			expr: &LogMetricExpr{
				metricOp: `count_over_time`,
				left: &LogRangeQueryExpr{
					rng:     `[24h]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							&LogFilterExpr{
								filter: "|=",
								value:  "error",
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
			input: `bytes_over_time(({first="value"} |= "other" |~ "loop" != "while" !~ "goto") [1m])`,
			expr: &LogMetricExpr{
				metricOp: "bytes_over_time",
				left: &LogRangeQueryExpr{
					rng:     `[1m]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							&LogFilterExpr{
								filter: "|=",
								value:  "other",
							},
							&LogFilterExpr{
								filter: "|~",
								value:  "loop",
							},
							&LogFilterExpr{
								filter: "!=",
								value:  "while",
							},
							&LogFilterExpr{
								filter: "!~",
								value:  "goto",
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
			input: `max without(value) (count_over_time({first="value"}[10h]))`,
			expr: &LogMetricExpr{
				metricOp:        "max",
				grouping:        &grouping{without: true, groups: []string{"value"}},
				groupingAfterOp: true,
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
				bytes_over_time(({first="value"} |= "other" |~ "loop" != "while" !~ "goto") [1m]),
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
								&LogFilterExpr{
									filter: "|=",
									value:  "other",
								},
								&LogFilterExpr{
									filter: "|~",
									value:  "loop",
								},
								&LogFilterExpr{
									filter: "!=",
									value:  "while",
								},
								&LogFilterExpr{
									filter: "!~",
									value:  "goto",
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
			input: `count_over_time(({title="martian"} |= "level=error") [1m]) / count_over_time({title="martian"}[1m])`,
			expr: LogBinaryOpExpr{
				Expr: &LogMetricExpr{
					metricOp: "count_over_time",
					left: &LogRangeQueryExpr{
						rng:     `[1m]`,
						rngLast: true,
						left: &LogQueryExpr{
							filter: LogPipelineExpr{
								&LogFilterExpr{
									filter: "|=",
									value:  "level=error",
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
			input: `sum by(job) (
							count_over_time(({title="martian"} |= "level=error") [1m])
						 /
							 bytes_over_time({title="martian"}[1m])
						) * 100`,
			expr: LogBinaryOpExpr{
				Expr: &LogMetricExpr{
					metricOp:        "sum",
					grouping:        &grouping{groups: []string{"job"}},
					groupingAfterOp: true,
					Expr: LogBinaryOpExpr{
						Expr: &LogMetricExpr{
							metricOp: "count_over_time",
							left: &LogRangeQueryExpr{
								rng:     `[1m]`,
								rngLast: true,
								left: &LogQueryExpr{
									filter: LogPipelineExpr{
										&LogFilterExpr{
											filter: "|=",
											value:  "level=error",
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
					sum(count_over_time({first="value"}[1m])) by(first) +
					 sum(bytes_over_time({first="value"}[1m])) by(first) /
					 sum(absent_over_time({first="value"}[1m])) by(first)
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
		{
			input: `
					sum by(lvl) (rate(({first="value"} | json | line_format "{{.message}}" | label_format lvl=level,txt="text: {{.message}}") [2m])) /
					 ignoring(lvl) group_left() sum(rate(({first="value"} | json | line_format "{{.message}}" | label_format lvl=level,txt="text: {{.message}}") [2m]))
				   `,
			expr: LogBinaryOpExpr{
				Expr: &LogMetricExpr{
					metricOp:        "sum",
					grouping:        &grouping{groups: []string{"lvl"}},
					groupingAfterOp: true,
					Expr: &LogMetricExpr{
						metricOp: "rate",
						left: &LogRangeQueryExpr{
							rng:     "[2m]",
							rngLast: true,
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
								filter: LogPipelineExpr{
									&LogParserExpr{
										parser: "json",
									},
									&LogParserExpr{
										parser:     "line_format",
										identifier: "{{.message}}",
									},
									&LogFormatExpr{
										sep: ",",
										kv: LogFormatValues{
											"lvl": LogFormatValue{Value: "level", IsIdentifier: true},
											"txt": LogFormatValue{Value: "text: {{.message}}"},
										},
									},
								},
							},
						},
					},
				},
				op: "/",
				modifier: BinaryOpOptions{
					IgnoringOption: IgnoringOption{
						Enabled:      true,
						Labels:       []string{"lvl"},
						GroupingType: GroupLeftOption,
					},
				},
				right: &LogMetricExpr{
					metricOp: "sum",
					Expr: &LogMetricExpr{
						metricOp: "rate",
						left: &LogRangeQueryExpr{
							rng:     "[2m]",
							rngLast: true,
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
								filter: LogPipelineExpr{
									&LogParserExpr{
										parser: "json",
									},
									&LogParserExpr{
										parser:     "line_format",
										identifier: "{{.message}}",
									},
									&LogFormatExpr{
										sep: ",",
										kv: LogFormatValues{
											"lvl": LogFormatValue{Value: "level", IsIdentifier: true},
											"txt": LogFormatValue{Value: "text: {{.message}}"},
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
			input: "100 ^ 100",
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
			input: `rate(({first="value"} | unwrap value) [30s])`,
			expr: &LogMetricExpr{
				metricOp: "rate",
				left: &LogRangeQueryExpr{
					rng:     `[30s]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							&LogParserExpr{
								parser:     "unwrap",
								identifier: "value",
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
			input: `sum_over_time(({first="value"} | unwrap bytes(value)) [5m])`,
			expr: &LogMetricExpr{
				metricOp: "sum_over_time",
				left: &LogRangeQueryExpr{
					rng:     `[5m]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							&LogParserExpr{
								parser:     "unwrap",
								identifier: "value",
								operation:  "bytes",
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
					&LogParserExpr{
						parser:     "line_format",
						identifier: "{{ __line__ }} bar {{.status_code}}",
					},
					&LogFormatExpr{
						sep: "",
						kv: LogFormatValues{
							"status_code": LogFormatValue{Value: "401"},
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
			input: `max_over_time(({first="value"} | unwrap value) [5m] offset 5m0s)`,
			expr: &LogMetricExpr{
				metricOp: "max_over_time",
				offset:   5 * time.Minute,
				left: &LogRangeQueryExpr{
					rng:     `[5m]`,
					rngLast: true,
					left: &LogQueryExpr{
						filter: LogPipelineExpr{
							&LogParserExpr{
								parser:     "unwrap",
								identifier: "value",
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
			input: `sum without(value) (quantile_over_time(0.98,({first="value"} | unwrap value) [5m] offset 5m0s) by(namespace))`,
			expr: &LogMetricExpr{
				metricOp:        "sum",
				grouping:        &grouping{without: true, groups: []string{"value"}},
				groupingAfterOp: true,
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
								&LogParserExpr{
									parser:     "unwrap",
									identifier: "value",
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
		// vector
		{
			input: `vector(0)`,
			expr: &LogMetricExpr{
				metricOp: OpTypeVector,
				Expr:     &VectorExpr{Value: "0"},
			},
		},
		{
			input: `vector(10) / vector(2)`,
			expr: LogBinaryOpExpr{
				Expr: &LogMetricExpr{
					metricOp: OpTypeVector,
					Expr:     &VectorExpr{Value: "10"},
				},
				op: "/",
				right: &LogMetricExpr{
					metricOp: OpTypeVector,
					Expr:     &VectorExpr{Value: "2"},
				},
			},
		},
		// decolorize
		{
			input: `{first="value"} | decolorize`,
			expr: &LogQueryExpr{
				filter: LogPipelineExpr{
					&LogDecolorizeExpr{},
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
	}
	for _, tc := range tc { //nolint:paralleltest
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			expr, err := ParseExpr(tc.input)

			if !errors.Is(tc.err, err) {
				t.Fatalf("unexpected err: %s", err)
			}

			got := trimOutput(expr.String())
			want := trimInput(tc.input)

			if want != got {
				t.Fatalf("\ngot:  %s\nwant: %s", got, want)
			}

			if !reflect.DeepEqual(tc.expr, expr) {
				t.Fatalf("\ngot:  %#v\nwant: %#v", expr, tc.expr)
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

func trimOutput(s string) string {
	if s == "" {
		return s
	}

	if strings.HasPrefix(s, "(") {
		s = strings.TrimPrefix(s, "(")
		s = strings.TrimSuffix(s, ")")
	}
	return s
}

func TestQuotesEncode(t *testing.T) {

	type tt struct {
		name  string
		input string
		want  string
	}

	tc := []tt{{
		name:  "parsed-backticks",
		input: "{app=\"test\"}|~`key\":\"val\"`",
		want:  `{app="test"} |~ "key\":\"val\""`,
	}, {
		name:  "parsed-double-quotes",
		input: `{app="test"}|~"key\":\"val\""`,
		want:  `{app="test"} |~ "key\":\"val\""`,
	}}

	for _, tc := range tc {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expr, err := ParseExpr(tc.input)
			if err != nil {
				t.Fatalf("unexpected err: %s", err)
			}
			got := expr.String()

			if tc.want != got {
				t.Fatalf("\ngot:  %s\nwant: %s", got, tc.want)
			}
		})
	}
}
