package v2

import (
	"errors"
	"strings"
	"sync"
	"text/scanner"
)

var (
	parserPool = sync.Pool{
		New: func() interface{} {
			//nolint:exhaustivestruct
			return &parser{
				p:      &exprParserImpl{},
				Reader: strings.NewReader(""),
				lexer:  &lexer{},
			}
		},
	}

	errNotCompatibleParserImpl = errors.New("not compatible parser implementation")
)

func init() {
	exprErrorVerbose = true
	exprDebug = 0
}

type parser struct {
	p *exprParserImpl
	*lexer
	expr Expr
	*strings.Reader
}

func ParseExpr(input string) (Expr, error) {
	p, ok := parserPool.Get().(*parser)
	if !ok {
		return nil, errNotCompatibleParserImpl
	}

	defer parserPool.Put(p)

	p.Reader.Reset(input)
	p.lexer.Init(p.Reader)
	p.lexer.errs = p.lexer.errs[:0]
	p.lexer.Scanner.Error = func(_ *scanner.Scanner, msg string) {
		p.lexer.Error(msg)
	}

	e := p.p.Parse(p)
	if e != 0 || len(p.lexer.errs) > 0 {
		return nil, p.lexer.errs[0]
	}

	return p.expr, nil
}
