package v2

import (
	"fmt"
	"strings"
	"text/scanner"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/prometheus/util/strutil"
)

const (
	VectorOpTypeSum     = "sum"
	VectorOpTypeAvg     = "avg"
	VectorOpTypeMax     = "max"
	VectorOpTypeMin     = "min"
	VectorOpTypeCount   = "count"
	VectorOpTypeStddev  = "stddev"
	VectorOpTypeStdvar  = "stdvar"
	VectorOpTypeBottomK = "bottomk"
	VectorOpTypeTopK    = "topk"

	RangeOpTypeCount     = "count_over_time"
	RangeOpTypeRate      = "rate"
	RangeOpTypeBytes     = "bytes_over_time"
	RangeOpTypeBytesRate = "bytes_rate"
	RangeOpTypeAvg       = "avg_over_time"
	RangeOpTypeSum       = "sum_over_time"
	RangeOpTypeMin       = "min_over_time"
	RangeOpTypeMax       = "max_over_time"
	RangeOpTypeStdvar    = "stdvar_over_time"
	RangeOpTypeStddev    = "stddev_over_time"
	RangeOpTypeQuantile  = "quantile_over_time"
	RangeOpTypeFirst     = "first_over_time"
	RangeOpTypeLast      = "last_over_time"
	RangeOpTypeAbsent    = "absent_over_time"

	// Other ops.
	OpLabelReplace = "label_replace"
	OpIP           = "ip"
)

// nolint:gochecknoglobals
var tokens = map[string]int{
	",":            COMMA,
	"{":            OPEN_BRACE,
	"}":            CLOSE_BRACE,
	"(":            OPEN_PARENTHESIS,
	")":            CLOSE_PARENTHESIS,
	"=":            EQ,
	"!=":           NEQ,
	"=~":           RE,
	"!~":           NRE,
	"|":            PIPE,
	"|=":           PIPE_EXACT,
	"|~":           PIPE_MATCH,
	"by":           BY,
	"without":      WITHOUT,
	"logfmt":       LOGFMT,
	"json":         JSON,
	"regexp":       REGEXP,
	"unpack":       UNPACK,
	"pattern":      PATTERN,
	"line_format":  LINE_FMT,
	"label_format": LABEL_FMT,
	"==":           CMP_EQ,
	">":            GT,
	">=":           GTE,
	"<":            LT,
	"<=":           LTE,
	"or":           OR,
	"and":          AND,
	"unless":       UNLESS,
	"+":            ADD,
	"-":            SUB,
	"*":            MUL,
	"/":            DIV,
	"%":            MOD,
	"^":            POW,
}

// nolint:gochecknoglobals
var funcTokens = map[string]int{
	// range vec ops
	RangeOpTypeRate:      RATE,
	RangeOpTypeCount:     COUNT_OVER_TIME,
	RangeOpTypeBytesRate: BYTES_RATE,
	RangeOpTypeBytes:     BYTES_OVER_TIME,
	RangeOpTypeAvg:       AVG_OVER_TIME,
	RangeOpTypeSum:       SUM_OVER_TIME,
	RangeOpTypeMin:       MIN_OVER_TIME,
	RangeOpTypeMax:       MAX_OVER_TIME,
	RangeOpTypeStdvar:    STDVAR_OVER_TIME,
	RangeOpTypeStddev:    STDDEV_OVER_TIME,
	RangeOpTypeQuantile:  QUANTILE_OVER_TIME,
	RangeOpTypeFirst:     FIRST_OVER_TIME,
	RangeOpTypeLast:      LAST_OVER_TIME,
	RangeOpTypeAbsent:    ABSENT_OVER_TIME,

	// vector ops
	VectorOpTypeSum:     SUM,
	VectorOpTypeAvg:     AVG,
	VectorOpTypeMax:     MAX,
	VectorOpTypeMin:     MIN,
	VectorOpTypeCount:   COUNT,
	VectorOpTypeStddev:  STDDEV,
	VectorOpTypeStdvar:  STDVAR,
	VectorOpTypeBottomK: BOTTOMK,
	VectorOpTypeTopK:    TOPK,

	OpLabelReplace: LABEL_REPLACE,
	OpIP:           IP,
}

type lexer struct {
	scanner.Scanner
	errs    []error
	builder strings.Builder
}

func (l *lexer) Error(msg string) {
	//nolint:goerr113
	l.errs = append(l.errs, fmt.Errorf("%s: %d:%d", msg, l.Line, l.Column))
}

//nolint:cyclop
func (l *lexer) Lex(lval *exprSymType) int {
	r := l.Scan()

	switch r {
	case '#':
		// Scan until a newline or EOF is encountered
		for next := l.Peek(); !(next == '\n' || next == scanner.EOF); next = l.Next() {
		}

		return l.Lex(lval)

	case scanner.EOF:
		return 0

	case scanner.Int, scanner.Float:
		numberText := l.TokenText()
		lval.str = numberText

		return NUMBER

	case scanner.String, scanner.RawString:
		var err error

		tokenText := l.TokenText()
		if !utf8.ValidString(tokenText) {
			l.Error("invalid UTF-8 rune")

			return 0
		}

		lval.str, err = strutil.Unquote(tokenText)
		if err != nil {
			l.Error(err.Error())

			return 0
		}

		return STRING
	}

	if r == '[' {
		l.builder.Reset()

		for r := l.Next(); r != scanner.EOF; r = l.Next() {
			if r == ']' {
				lval.str = "[" + l.builder.String() + "]"

				return RANGE
			}

			_, _ = l.builder.WriteRune(r)
		}

		l.Error("missing closing ']' in duration")

		return 0
	}

	tokenText := l.TokenText()
	tokenNext := tokenText + string(l.Peek())

	if tok, ok := funcTokens[tokenNext]; ok {
		sc := l.Scanner
		sc.Next()

		if isFunc(sc) {
			l.Next()

			return tok
		}
	}

	if tok, ok := funcTokens[tokenText]; ok && isFunc(l.Scanner) {
		return tok
	}

	if tok, ok := tokens[tokenNext]; ok {
		l.Next()

		return tok
	}

	if tok, ok := tokens[tokenText]; ok {
		return tok
	}

	lval.str = tokenText

	return IDENTIFIER
}

func isFunc(sc scanner.Scanner) bool {
	var sb strings.Builder

	sc = trimSpace(sc)

	for r := sc.Next(); r != scanner.EOF; r = sc.Next() {
		sb.WriteRune(r)

		switch sb.String() {
		case "(":
			return true

		case "by", "without":
			sc = trimSpace(sc)

			return sc.Next() == '('
		}
	}

	return false
}

func trimSpace(s scanner.Scanner) scanner.Scanner {
	for n := s.Peek(); n != scanner.EOF; n = s.Peek() {
		if unicode.IsSpace(n) {
			s.Next()

			continue
		}

		return s
	}

	return s
}
