// nolint:exhaustivestruct
package v2

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/labels"
)

type WalkFn = func(e interface{})

type Walker interface {
	Walk(f WalkFn)
}

type Expr interface {
	logQLExpr()
	fmt.Stringer
	Walker
}

type LogSelectorExpr interface {
	Matchers() []*labels.Matcher
	Expr
}

type LogMetricSampleExpr interface {
	Selector() LogSelectorExpr
	Expr
}

type defaultLogQLExpr struct{}

func (defaultLogQLExpr) logQLExpr() {}

type StreamMatcherExpr struct {
	defaultLogQLExpr
	matchers []*labels.Matcher
}

func newStreamMatcherExpr(matchers []*labels.Matcher) *StreamMatcherExpr {
	return &StreamMatcherExpr{matchers: matchers}
}

func (s *StreamMatcherExpr) Matchers() []*labels.Matcher {
	return s.matchers
}

func (s *StreamMatcherExpr) AppendMatchers(m []*labels.Matcher) {
	s.matchers = append(s.matchers, m...)
}

func (s *StreamMatcherExpr) SetMatchers(m []*labels.Matcher) {
	s.matchers = m
}

func (s *StreamMatcherExpr) Walk(fn WalkFn) {
	fn(s)
}

func (s *StreamMatcherExpr) String() string {
	var sb strings.Builder

	sb.WriteString("{")

	for i, m := range s.matchers {
		sb.WriteString(m.String())

		if i+1 != len(s.matchers) {
			sb.WriteString(", ")
		}
	}

	sb.WriteString("}")

	return sb.String()
}

func newLabelMatcher(t labels.MatchType, n, v string) *labels.Matcher {
	m, err := labels.NewMatcher(t, n, v)
	if err != nil {
		panic(err.Error())
	}

	return m
}

type LogFilterExpr struct {
	defaultLogQLExpr // nolint:unused
	filter           string
	filterOp         string
	value            string
}

func (LogFilterExpr) logQLExpr() {}

func (LogFilterExpr) logStageExpr() {}

func newLogFilterExpr(filter, filterOp, value string) *LogFilterExpr {
	return &LogFilterExpr{filter: filter, filterOp: filterOp, value: value}
}

func (l *LogFilterExpr) String() string {
	var sb strings.Builder

	sb.WriteString(l.filter)
	sb.WriteString(" ")

	if l.filterOp != "" {
		sb.WriteString(l.filterOp)
		sb.WriteString("(")
		sb.WriteString(strconv.Quote(l.value))
		sb.WriteString(")")
	} else {
		sb.WriteString(strconv.Quote(l.value))
	}

	return sb.String()
}

func (l *LogFilterExpr) Walk(fn WalkFn) {
	fn(l)
}

type LogLabelFilterExpr struct {
	defaultLogQLExpr // nolint:unused
	labelName        string
	comparisonOp     string
	filterOp         string
	labelValue       string
	isNested         bool
	chainOp          string
	right            []*LogLabelFilterExpr
}

func newLogLabelFilter(identifier, comparisonOp, filterOp, value string) *LogLabelFilterExpr {
	return &LogLabelFilterExpr{labelName: identifier, comparisonOp: comparisonOp, filterOp: filterOp, labelValue: value}
}

func (LogLabelFilterExpr) logQLExpr() {}

func (LogLabelFilterExpr) logStageExpr() {}

func (l *LogLabelFilterExpr) chain(op string, expr *LogLabelFilterExpr) *LogLabelFilterExpr {
	expr.isNested = true
	expr.chainOp = op
	l.right = append(l.right, expr)

	return l
}

func (l *LogLabelFilterExpr) String() string {
	var sb strings.Builder

	if !l.isNested {
		sb.WriteString("| ")
	}

	sb.WriteString(l.labelName)
	sb.WriteString(l.comparisonOp)

	if l.filterOp != "" {
		sb.WriteString(l.filterOp)
		sb.WriteString("(")
		sb.WriteString(`"`)
		sb.WriteString(l.labelValue)
		sb.WriteString(`"`)
		sb.WriteString(")")
	} else {
		sb.WriteString(`"`)
		sb.WriteString(l.labelValue)
		sb.WriteString(`"`)
	}

	for i, r := range l.right {
		switch r.chainOp {
		case "and", "or":
			sb.WriteString(" ")
			sb.WriteString(r.chainOp)
			sb.WriteString(" ")
			sb.WriteString(r.String())
		case ",":
			sb.WriteString(r.chainOp)
			sb.WriteString(" ")
			sb.WriteString(r.String())
		}

		if i == len(l.right) {
			sb.WriteString(" ")
		}
	}

	return sb.String()
}

func (l *LogLabelFilterExpr) Walk(fn WalkFn) {
	fn(l)

	for _, r := range l.right {
		fn(r)
	}
}

type LogFormatValue struct {
	Value        string
	IsIdentifier bool
}

type LogFormatValues map[string]LogFormatValue

func (l *LogFormatValues) Walk(fn WalkFn) {
	if l == nil {
		return
	}

	for _, e := range *l {
		fn(e)
	}
}

type LogStageExpr interface {
	logStageExpr()
	String() string
}

type LogFormatExpr struct {
	defaultLogQLExpr // nolint:unused
	kv               LogFormatValues
	sep              string
	operation        string
}

//nolint:unparam
func newLogFormatExpr(sep string, kv LogFormatValues, operation string) *LogFormatExpr {
	return &LogFormatExpr{sep: sep, kv: kv, operation: operation}
}

func (LogFormatExpr) logQLExpr() {}

func (LogFormatExpr) logStageExpr() {}

func (l *LogFormatExpr) String() string {
	var (
		sb strings.Builder
		i  int
	)

	sb.WriteString(fmt.Sprintf("| %s ", ParserLabelFormat))

	keys := make([]string, 0, len(l.kv))
	for key := range l.kv {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		if key != "" {
			sb.WriteString(key)
			sb.WriteString("=")
		}

		if l.operation != "" {
			sb.WriteString(fmt.Sprintf("%s(", l.operation))
		}

		lmv := l.kv[key]
		val := lmv.Value
		if !lmv.IsIdentifier {
			val = strconv.Quote(lmv.Value)
		}

		sb.WriteString(val)

		if l.operation != "" {
			sb.WriteString(")")
		}

		if i+1 != len(l.kv) {
			sb.WriteString(l.sep)
		}

		i++
	}

	return sb.String()
}

func (l *LogFormatExpr) Walk(fn WalkFn) {
	fn(l)
}

func mergeLogFormatValues(lhs, rhs LogFormatValues) LogFormatValues {
	for rk, rv := range rhs {
		lhs[rk] = rv
	}

	return lhs
}

type LogParserExpr struct {
	defaultLogQLExpr // nolint:unused
	identifier       string
	parser           string
	operation        string
}

func newLogParserExpr(parser, identifier, operation string) *LogParserExpr {
	return &LogParserExpr{parser: parser, identifier: identifier, operation: operation}
}

func (LogParserExpr) logQLExpr() {}

func (LogParserExpr) logStageExpr() {}

func (l *LogParserExpr) String() string {
	var sb strings.Builder
	sb.WriteString("| ")
	sb.WriteString(l.parser)

	if l.operation != "" {
		sb.WriteString(fmt.Sprintf(" %s(", l.operation))
	}

	switch l.parser {
	case ParserRegExp, ParserLineFormat:
		sb.WriteString(" ")
		sb.WriteString(strconv.Quote(l.identifier))
	case ParserPattern:
		sb.WriteString(" ")
		if strings.Contains(l.identifier, `"`) {
			sb.WriteString("`")
			sb.WriteString(l.identifier)
			sb.WriteString("`")
		} else {
			sb.WriteString(strconv.Quote(l.identifier))
		}
	case ParserUnwrap:
		if l.operation == "" {
			sb.WriteString(" ")
		}
		sb.WriteString(l.identifier)
	default:
		sb.WriteString(l.identifier)
	}

	if l.operation != "" {
		sb.WriteString(")")
	}

	return sb.String()
}

func (l *LogParserExpr) Walk(fn WalkFn) {
	fn(l)
}

type LogDecolorizeExpr struct {
	defaultLogQLExpr // nolint:unused
}

func newLogDecolorizeExpr() *LogDecolorizeExpr {
	return &LogDecolorizeExpr{}
}

func (LogDecolorizeExpr) logQLExpr() {}

func (LogDecolorizeExpr) logStageExpr() {}

func (l LogDecolorizeExpr) String() string {
	return "| decolorize"
}

func (l *LogDecolorizeExpr) Walk(fn WalkFn) {
	fn(l)
}

type LogPipelineExpr []LogStageExpr

func (LogPipelineExpr) logQLExpr() {}

func (l LogPipelineExpr) String() string {
	var sb strings.Builder

	for i, p := range l {
		sb.WriteString(p.String())

		if i+1 != len(l) {
			sb.WriteString(" ")
		}
	}

	return sb.String()
}

func (l *LogPipelineExpr) Walk(fn WalkFn) {
	if l == nil {
		return
	}

	for _, e := range *l {
		fn(e)
	}
}

type LogQueryExpr struct {
	defaultLogQLExpr // nolint:unused
	left             *StreamMatcherExpr
	filter           LogPipelineExpr
	Expr
}

func newLogQueryExpr(m *StreamMatcherExpr, filter LogPipelineExpr) LogSelectorExpr {
	return &LogQueryExpr{left: m, filter: filter}
}

func (LogQueryExpr) logQLExpr() {}

func (l *LogQueryExpr) Matchers() []*labels.Matcher {
	return l.left.matchers
}

func (l *LogQueryExpr) AppendPipelineMatchers(matchers []*labels.Matcher, chainOp string) {
	if len(matchers) == 0 {
		return
	}
	matchersFilter := LogLabelFilterExpr{
		labelName:    matchers[0].Name,
		comparisonOp: matchers[0].Type.String(),
		labelValue:   matchers[0].Value,
	}
	for _, m := range matchers[1:] {
		matchersFilter.right = append(matchersFilter.right, &LogLabelFilterExpr{
			labelName:    m.Name,
			comparisonOp: m.Type.String(),
			labelValue:   m.Value,
			isNested:     true,
			chainOp:      chainOp,
		})
	}
	l.filter = append(LogPipelineExpr{&matchersFilter}, l.filter...)
}

func (l *LogQueryExpr) String() string {
	var sb strings.Builder

	sb.WriteString(l.left.String())

	if l.filter != nil {
		sb.WriteString(" ")
		sb.WriteString(l.filter.String())
	}

	return sb.String()
}

func (l *LogQueryExpr) Walk(fn WalkFn) {
	fn(l)
	l.left.Walk(fn)
}

type LogRangeQueryExpr struct {
	defaultLogQLExpr // nolint:unused
	left             LogSelectorExpr
	rng              string
	grouping         *grouping
	rngLast          bool
	Expr
}

func newLogRangeQueryExpr(m LogSelectorExpr, rng string, grouping *grouping, rngLast bool) LogSelectorExpr {
	return &LogRangeQueryExpr{left: m, rng: rng, grouping: grouping, rngLast: rngLast}
}

func (LogRangeQueryExpr) logQLExpr() {}

func (l *LogRangeQueryExpr) Matchers() []*labels.Matcher {
	return l.left.Matchers()
}

func (l *LogRangeQueryExpr) String() string {
	var sb strings.Builder

	if l.grouping != nil {
		sb.WriteString("(")
	}

	if l.rngLast {
		sb.WriteString("(")
		sb.WriteString(l.left.String())
		sb.WriteString(") ")
		sb.WriteString(l.rng)
	} else {
		sl := strings.Replace(l.left.String(), "}", fmt.Sprintf("}%s", l.rng), 1)
		sb.WriteString(sl)
	}

	if l.grouping != nil {
		sb.WriteString(") ")
		sb.WriteString(l.grouping.String())
	}

	return sb.String()
}

func (l *LogRangeQueryExpr) Walk(fn WalkFn) {
	fn(l)
	l.left.Walk(fn)
}

type LogMetricExpr struct {
	defaultLogQLExpr // nolint:unused
	left             LogSelectorExpr
	metricOp         string
	preamble         string
	grouping         *grouping
	groupingAfterOp  bool
	params           []string
	offset           time.Duration
	Expr
}

func newLogMetricExpr(
	e Expr,
	m LogSelectorExpr,
	op, preamble string,
	grouping *grouping,
	groupingAfterOp bool,
	params []string,
	o *LogOffsetExpr,
) LogMetricSampleExpr {
	var offset time.Duration
	if o != nil {
		offset = o.Offset
	}
	return &LogMetricExpr{
		Expr:            e,
		left:            m,
		metricOp:        op,
		preamble:        preamble,
		grouping:        grouping,
		groupingAfterOp: groupingAfterOp,
		params:          params,
		offset:          offset,
	}
}

func (LogMetricExpr) logQLExpr() {}

func (l *LogMetricExpr) Selector() LogSelectorExpr {
	return l.left
}

func (l *LogMetricExpr) String() string {
	var sb strings.Builder

	sb.WriteString(l.metricOp)

	if l.grouping != nil && l.groupingAfterOp {
		sb.WriteString(l.grouping.String())
		sb.WriteString(" ")
	}

	sb.WriteString("(")

	if l.preamble != "" {
		sb.WriteString(l.preamble)
		sb.WriteString(",")
	}

	if l.Expr != nil {
		sb.WriteString(l.Expr.String())
	} else {
		sb.WriteString(l.left.String())
	}

	if l.metricOp == OpLabelReplace {
		sb.WriteString(",")

		for i, p := range l.params {
			sb.WriteString(`"`)
			sb.WriteString(p)
			sb.WriteString(`"`)

			if i+1 != len(l.params) {
				sb.WriteString(",")
			}
		}
	}

	if l.offset != 0 {
		offsetExpr := LogOffsetExpr{Offset: l.offset}
		sb.WriteString(offsetExpr.String())
	}

	sb.WriteString(")")

	if l.grouping != nil && !l.groupingAfterOp {
		sb.WriteString(l.grouping.String())
	}

	return sb.String()
}

func (l *LogMetricExpr) Walk(fn WalkFn) {
	fn(l)

	if l.Expr != nil {
		l.Expr.Walk(fn)
	}

	if l.left != nil {
		l.left.Walk(fn)
	}
}

type grouping struct {
	without bool
	groups  []string
}

func (g grouping) String() string {
	var sb strings.Builder
	if g.without {
		sb.WriteString(" without")
	} else if len(g.groups) > 0 {
		sb.WriteString(" by")
	}

	if len(g.groups) > 0 {
		sb.WriteString("(")
		sb.WriteString(strings.Join(g.groups, ","))
		sb.WriteString(")")
	}

	return sb.String()
}

type LogBinaryOpExpr struct {
	defaultLogQLExpr // nolint:unused
	op               string
	modifier         BinaryOpOptions
	right            Expr
	Expr
}

type GroupingOptionType string

const (
	GroupLeftOption  GroupingOptionType = "group_left"
	GroupRightOption GroupingOptionType = "group_right"
)

type OnOption struct {
	Enabled       bool
	Labels        []string
	GroupingType  GroupingOptionType
	IncludeLabels []string
}

type IgnoringOption struct {
	Enabled       bool
	Labels        []string
	GroupingType  GroupingOptionType
	IncludeLabels []string
}

type BinaryOpOptions struct {
	ReturnBool     bool
	IgnoringOption IgnoringOption
	OnOption       OnOption
}

func newLogBinaryOpExpr(op string, modifier BinaryOpOptions, left, right Expr) LogBinaryOpExpr {
	return LogBinaryOpExpr{op: op, modifier: modifier, Expr: left, right: right}
}

func (LogBinaryOpExpr) logQLExpr() {}

func (l LogBinaryOpExpr) String() string {
	var sb strings.Builder

	sb.WriteString(l.Expr.String())
	sb.WriteString(" ")
	sb.WriteString(l.op)
	sb.WriteString(" ")

	if l.modifier.ReturnBool {
		sb.WriteString("bool")
		sb.WriteString(" ")
	}

	if l.modifier.IgnoringOption.Enabled {
		sb.WriteString("ignoring")
		sb.WriteString("(")
		sb.WriteString(strings.Join(l.modifier.IgnoringOption.Labels, ","))
		sb.WriteString(")")

		switch l.modifier.IgnoringOption.GroupingType {
		case GroupLeftOption:
			sb.WriteString(" ")
			sb.WriteString(string(GroupLeftOption))
			sb.WriteString("(")
			sb.WriteString(strings.Join(l.modifier.IgnoringOption.IncludeLabels, ","))
			sb.WriteString(")")
		case GroupRightOption:
			sb.WriteString(" ")
			sb.WriteString(string(GroupRightOption))
			sb.WriteString("(")
			sb.WriteString(strings.Join(l.modifier.IgnoringOption.IncludeLabels, ","))
			sb.WriteString(")")
		default:
			// do nothing
		}
		sb.WriteString(" ")
	}

	if l.modifier.OnOption.Enabled {
		sb.WriteString("on")
		sb.WriteString("(")
		sb.WriteString(strings.Join(l.modifier.OnOption.Labels, ","))
		sb.WriteString(")")

		switch l.modifier.OnOption.GroupingType {
		case GroupLeftOption:
			sb.WriteString(" ")
			sb.WriteString(string(GroupLeftOption))
			sb.WriteString("(")
			sb.WriteString(strings.Join(l.modifier.OnOption.IncludeLabels, ","))
			sb.WriteString(")")
		case GroupRightOption:
			sb.WriteString(" ")
			sb.WriteString(string(GroupRightOption))
			sb.WriteString("(")
			sb.WriteString(strings.Join(l.modifier.OnOption.IncludeLabels, ","))
			sb.WriteString(")")
		default:
			// do nothing
		}

		sb.WriteString(" ")
	}

	sb.WriteString(l.right.String())

	return sb.String()
}

func (l LogBinaryOpExpr) Walk(fn WalkFn) {
	fn(l)
	l.Expr.Walk(fn)
	l.right.Walk(fn)
}

type LogNumberExpr struct {
	defaultLogQLExpr // nolint:unused
	value            float64
	isNeg            bool
	Expr
}

func (LogNumberExpr) logQLExpr() {}

func newLogNumberExpr(value string, isNegative bool) LogNumberExpr {
	n, _ := strconv.ParseFloat(value, 64) //nolint:gomnd

	return LogNumberExpr{value: n, isNeg: isNegative}
}

func (l LogNumberExpr) String() string {
	format := "%f"
	if l.isNeg {
		format = "-" + format
	}

	return strings.TrimRight(strings.TrimRight(fmt.Sprintf(format, l.value), "0"), ".")
}

func (l LogNumberExpr) Walk(fn WalkFn) {
	fn(l)
}

type LogOffsetExpr struct {
	Offset time.Duration
}

func (o *LogOffsetExpr) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(" %s %s", "offset", o.Offset.String()))
	return sb.String()
}

func newLogOffsetExpr(offset time.Duration) *LogOffsetExpr {
	return &LogOffsetExpr{
		Offset: offset,
	}
}

type VectorExpr struct {
	defaultLogQLExpr // nolint:unused
	Value            string
}

func (*VectorExpr) logQLExpr() {}

func newVectorExpr(val string) *VectorExpr {
	return &VectorExpr{Value: val}
}

func (v *VectorExpr) String() string {
	return v.Value
}

func (v *VectorExpr) Walk(fn WalkFn) { fn(v) }
