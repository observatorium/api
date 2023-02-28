%{
package v2

import (
  "time"
  "github.com/prometheus/prometheus/pkg/labels"
)
%}

%union{
  Expr                 Expr
  LogBinaryOpExpr      LogBinaryOpExpr
  LogFilterExpr        *LogFilterExpr
  LogLabelFilterExpr   *LogLabelFilterExpr
  LogFormatExpr        *LogFormatExpr
  LogQueryExpr         LogSelectorExpr
  LogMetricExpr        LogMetricSampleExpr
  LogNumberExpr        LogNumberExpr
  LogPipelineExpr      LogPipelineExpr
  LogStageExpr         LogStageExpr
  LogRangeQueryExpr    LogSelectorExpr
  LogOffsetExpr        *LogOffsetExpr
  Matcher              *labels.Matcher
  Matchers             []*labels.Matcher
  MetricOp             string
  BinaryOpOptions      BinaryOpOptions
  Range                string
  Filter               string
  Selector             []*labels.Matcher
  Grouping             *grouping
  Labels               []string
  str                  string
  binaryOp             string
  ComparisonOp         string
  duration             time.Duration
  ConvOp               string
}

%start root

%type <BinaryOpOptions>      binaryOpOptions
%type <ComparisonOp>         comparisonOp
%type <Expr>                 expr
%type <Filter>               filter
%type <Labels>               labels
%type <LogBinaryOpExpr>      logBinaryOpExpr
%type <LogFilterExpr>        logFilterExpr
%type <LogLabelFilterExpr>   logLabelFilterExpr
%type <LogFormatExpr>        logFormatExpr
%type <LogQueryExpr>         logQueryExpr
%type <LogMetricExpr>        logMetricExpr
%type <LogNumberExpr>        logNumberExpr
%type <LogPipelineExpr>      logPipelineExpr
%type <LogStageExpr>         logStageExpr
%type <LogRangeQueryExpr>    logRangeQueryExpr
%type <LogOffsetExpr>        logOffsetExpr
%type <Matcher>              matcher
%type <Matchers>             matchers
%type <MetricOp>             metricOp
%type <Selector>             selector
%type <Grouping>             grouping
%type <ConvOp>               convOp

%token  <str>      IDENTIFIER STRING RANGE NUMBER
%token  <duration> DURATION
%token  <val>      MATCHERS LABELS EQ RE NRE OPEN_BRACE CLOSE_BRACE OPEN_BRACKET CLOSE_BRACKET COMMA DOT
                   OPEN_PARENTHESIS CLOSE_PARENTHESIS COUNT_OVER_TIME RATE RATE_COUNTER SUM AVG MAX MIN COUNT STDDEV STDVAR BOTTOMK TOPK
                   BYTES_OVER_TIME BYTES_RATE BOOL JSON REGEXP LOGFMT PIPE_MATCH PIPE_EXACT PIPE LINE_FMT LABEL_FMT UNWRAP AVG_OVER_TIME SUM_OVER_TIME MIN_OVER_TIME
                   MAX_OVER_TIME STDVAR_OVER_TIME STDDEV_OVER_TIME QUANTILE_OVER_TIME FIRST_OVER_TIME LAST_OVER_TIME ABSENT_OVER_TIME
                   BY WITHOUT VECTOR LABEL_REPLACE IP UNPACK PATTERN OFFSET BYTES_CONV DURATION_CONV DURATION_SECONDS_CONV ON IGNORING GROUP_LEFT GROUP_RIGHT
                   DECOLORIZE

%left <binaryOp> OR
%left <binaryOp> AND UNLESS
%left <binaryOp> CMP_EQ NEQ LT LTE GT GTE
%left <binaryOp> ADD SUB
%left <binaryOp> MUL DIV MOD
%right <binaryOp> POW
%%

root: expr { exprlex.(*parser).expr = $1 };

expr:
                logQueryExpr    { $$ = $1 }
        |       logMetricExpr   { $$ = $1 }
        |       logBinaryOpExpr { $$ = $1 }
        |       logNumberExpr   { $$ = $1 }
        ;

logQueryExpr:
                selector                                         { $$ = newLogQueryExpr(newStreamMatcherExpr($1), nil) }
        |       selector logPipelineExpr                         { $$ = newLogQueryExpr(newStreamMatcherExpr($1), $2)  }
        |       OPEN_PARENTHESIS logQueryExpr CLOSE_PARENTHESIS  { $$ = $2                                             }
        ;

logPipelineExpr:
                logStageExpr                 { $$ = LogPipelineExpr { $1 } }
        |       logPipelineExpr logStageExpr { $$ = append($1, $2)         }
        ;

convOp:
            BYTES_CONV              { $$ = OpConvBytes           }
        |   DURATION_CONV           { $$ = OpConvDuration        }
        |   DURATION_SECONDS_CONV   { $$ = OpConvDurationSeconds }
        ;

logStageExpr:
                logFilterExpr                                                             { $$ = $1                                         }
        |       PIPE logLabelFilterExpr                                                   { $$ = $2                                         }
        |       PIPE LOGFMT                                                               { $$ = newLogParserExpr(ParserLogFMT, "", "")     }
        |       PIPE JSON                                                                 { $$ = newLogParserExpr(ParserJSON, "", "")       }
        |       PIPE UNPACK                                                               { $$ = newLogParserExpr(ParserUnpack, "", "")     }
        |       PIPE UNWRAP IDENTIFIER                                                    { $$ = newLogParserExpr(ParserUnwrap, $3, "")     }
        |       PIPE UNWRAP convOp OPEN_PARENTHESIS IDENTIFIER CLOSE_PARENTHESIS          { $$ = newLogParserExpr(ParserUnwrap, $5, $3)     }
        |       PIPE REGEXP STRING                                                        { $$ = newLogParserExpr(ParserRegExp, $3, "")     }
        |       PIPE PATTERN STRING                                                       { $$ = newLogParserExpr(ParserPattern, $3, "")    }
        |       PIPE LINE_FMT STRING                                                      { $$ = newLogParserExpr(ParserLineFormat, $3, "") }
        |       PIPE DECOLORIZE                                                           { $$ = newLogDecolorizeExpr()                     }
        |       PIPE LABEL_FMT logFormatExpr                                              { $$ = $3                                         }
        ;

logFilterExpr:
                filter STRING                                       { $$ = newLogFilterExpr($1, "", $2)   }
        |       filter IP OPEN_PARENTHESIS STRING CLOSE_PARENTHESIS { $$ = newLogFilterExpr($1, OpIP, $4) }
        ;

logLabelFilterExpr:
                IDENTIFIER comparisonOp STRING                                       { $$ = newLogLabelFilter($1, $2, "", $3)   }
        |       IDENTIFIER comparisonOp IP OPEN_PARENTHESIS STRING CLOSE_PARENTHESIS { $$ = newLogLabelFilter($1, $2, OpIP, $5) }
        |       logLabelFilterExpr AND logLabelFilterExpr                            { $$ = $1.chain("and", $3)                 }
        |       logLabelFilterExpr OR logLabelFilterExpr                             { $$ = $1.chain("or", $3)                  }
        |       logLabelFilterExpr COMMA logLabelFilterExpr                          { $$ = $1.chain(",", $3)                   }
        ;

logFormatExpr:
                IDENTIFIER EQ STRING                                       { $$ = newLogFormatExpr("", LogFormatValues{$1: LogFormatValue{Value: $3}}, "")                     }
        |       IDENTIFIER EQ IDENTIFIER                                   { $$ = newLogFormatExpr("", LogFormatValues{$1: LogFormatValue{Value: $3, IsIdentifier: true}}, "") }
        |       IDENTIFIER EQ IP OPEN_PARENTHESIS STRING CLOSE_PARENTHESIS { $$ = newLogFormatExpr("", LogFormatValues{$1: LogFormatValue{Value: OpIP+"("+$5+")"}}, "")        }
        |       logFormatExpr COMMA logFormatExpr                          { $$ = newLogFormatExpr(",", mergeLogFormatValues($1.kv, $3.kv), "")                                }
        ;

logOffsetExpr:
                OFFSET DURATION { $$ = newLogOffsetExpr($2) }
        ;

logRangeQueryExpr:
                selector RANGE                                                             { $$ = newLogRangeQueryExpr(newLogQueryExpr(newStreamMatcherExpr($1), nil), $2, nil, false) }
        |       selector RANGE logPipelineExpr                                             { $$ = newLogRangeQueryExpr(newLogQueryExpr(newStreamMatcherExpr($1), $3), $2, nil, false)  }
        |       selector logPipelineExpr RANGE                                             { $$ = newLogRangeQueryExpr(newLogQueryExpr(newStreamMatcherExpr($1), $2), $3, nil, true)   }
        |       OPEN_PARENTHESIS selector RANGE CLOSE_PARENTHESIS                          { $$ = newLogRangeQueryExpr(newLogQueryExpr(newStreamMatcherExpr($2), nil), $3, nil, false) }
        |       OPEN_PARENTHESIS selector RANGE logPipelineExpr CLOSE_PARENTHESIS          { $$ = newLogRangeQueryExpr(newLogQueryExpr(newStreamMatcherExpr($2), $4), $3, nil, false)  }
        |       OPEN_PARENTHESIS selector logPipelineExpr CLOSE_PARENTHESIS RANGE          { $$ = newLogRangeQueryExpr(newLogQueryExpr(newStreamMatcherExpr($2), $3), $5, nil, true)   }
        |       OPEN_PARENTHESIS selector RANGE logPipelineExpr CLOSE_PARENTHESIS grouping { $$ = newLogRangeQueryExpr(newLogQueryExpr(newStreamMatcherExpr($2), $4), $3, $6, false)   }
        |       logRangeQueryExpr error
        ;

logMetricExpr:
                metricOp OPEN_PARENTHESIS logRangeQueryExpr CLOSE_PARENTHESIS                                                        { $$ = newLogMetricExpr(nil, $3, $1, "", nil, false, nil, nil)                                }
        |       metricOp OPEN_PARENTHESIS logRangeQueryExpr logOffsetExpr CLOSE_PARENTHESIS                                          { $$ = newLogMetricExpr(nil, $3, $1, "", nil, false, nil, $4)                                 }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logRangeQueryExpr CLOSE_PARENTHESIS                                           { $$ = newLogMetricExpr(nil, $5, $1, $3, nil, false, nil, nil)                                }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logRangeQueryExpr CLOSE_PARENTHESIS grouping                                  { $$ = newLogMetricExpr(nil, $5, $1, $3, $7, false, nil, nil)                                 }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logRangeQueryExpr logOffsetExpr CLOSE_PARENTHESIS                             { $$ = newLogMetricExpr(nil, $5, $1, $3, nil, false, nil, $6)                                 }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logRangeQueryExpr logOffsetExpr CLOSE_PARENTHESIS grouping                    { $$ = newLogMetricExpr(nil, $5, $1, $3, $8, false, nil, $6)                                  }
        |       metricOp OPEN_PARENTHESIS logRangeQueryExpr CLOSE_PARENTHESIS grouping                                               { $$ = newLogMetricExpr(nil, $3, "", "", $5, false, nil, nil)                                 }
        |       metricOp OPEN_PARENTHESIS logRangeQueryExpr logOffsetExpr CLOSE_PARENTHESIS grouping                                 { $$ = newLogMetricExpr(nil, $3, "", "", $6, false, nil, $4)                                  }
        |       metricOp OPEN_PARENTHESIS logMetricExpr CLOSE_PARENTHESIS grouping                                                   { $$ = newLogMetricExpr($3, nil, $1, "", $5, false, nil, nil)                                 }
        |       metricOp OPEN_PARENTHESIS logMetricExpr CLOSE_PARENTHESIS                                                            { $$ = newLogMetricExpr($3, nil, $1, "", nil, false, nil, nil)                                }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logMetricExpr CLOSE_PARENTHESIS                                               { $$ = newLogMetricExpr($5, nil, $1, $3, nil, false, nil, nil)                                }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logMetricExpr CLOSE_PARENTHESIS grouping                                      { $$ = newLogMetricExpr($5, nil, $1, $3, $7, false, nil, nil)                                 }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logMetricExpr logOffsetExpr CLOSE_PARENTHESIS grouping                        { $$ = newLogMetricExpr($5, nil, $1, $3, $8, false, nil, $6)                                  }
        |       metricOp grouping OPEN_PARENTHESIS NUMBER COMMA logMetricExpr CLOSE_PARENTHESIS                                      { $$ = newLogMetricExpr($6, nil, $1, $4, $2, true, nil, nil)                                  }
        |       metricOp grouping OPEN_PARENTHESIS logMetricExpr CLOSE_PARENTHESIS                                                   { $$ = newLogMetricExpr($4, nil, $1, "", $2, true, nil, nil)                                  }
        |       metricOp grouping OPEN_PARENTHESIS logMetricExpr logOffsetExpr CLOSE_PARENTHESIS                                     { $$ = newLogMetricExpr($4, nil, $1, "", $2, true, nil, $5)                                   }
        |       LABEL_REPLACE OPEN_PARENTHESIS logMetricExpr COMMA STRING COMMA STRING COMMA STRING COMMA STRING CLOSE_PARENTHESIS   { $$ = newLogMetricExpr($3, nil, OpLabelReplace, "", nil, false, []string{$5,$7,$9,$11}, nil) }
        |       metricOp OPEN_PARENTHESIS logBinaryOpExpr CLOSE_PARENTHESIS grouping                                                 { $$ = newLogMetricExpr($3, nil, $1, "", $5, false, nil, nil)                                 }
        |       metricOp OPEN_PARENTHESIS logBinaryOpExpr CLOSE_PARENTHESIS                                                          { $$ = newLogMetricExpr($3, nil, $1, "", nil, false, nil, nil)                                }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logBinaryOpExpr CLOSE_PARENTHESIS                                             { $$ = newLogMetricExpr($5, nil, $1, $3, nil, false, nil, nil)                                }
        |       metricOp OPEN_PARENTHESIS NUMBER COMMA logBinaryOpExpr CLOSE_PARENTHESIS grouping                                    { $$ = newLogMetricExpr($5, nil, $1, $3, $7, false, nil, nil)                                 }
        |       metricOp grouping OPEN_PARENTHESIS NUMBER COMMA logBinaryOpExpr CLOSE_PARENTHESIS                                    { $$ = newLogMetricExpr($6, nil, $1, $4, $2, true, nil, nil)                                  }
        |       metricOp grouping OPEN_PARENTHESIS logBinaryOpExpr CLOSE_PARENTHESIS                                                 { $$ = newLogMetricExpr($4, nil, $1, "", $2, true, nil, nil)                                  }
        |       LABEL_REPLACE OPEN_PARENTHESIS logBinaryOpExpr COMMA STRING COMMA STRING COMMA STRING COMMA STRING CLOSE_PARENTHESIS { $$ = newLogMetricExpr($3, nil, OpLabelReplace, "", nil, false, []string{$5,$7,$9,$11}, nil) }
        |       metricOp OPEN_PARENTHESIS NUMBER CLOSE_PARENTHESIS                                                                   { $$ = newLogMetricExpr(newVectorExpr($3), nil, OpTypeVector, "", nil, false, nil, nil)       }
        |       OPEN_PARENTHESIS logMetricExpr CLOSE_PARENTHESIS                                                                     { $$ = $2                                                                                     }
        ;

logBinaryOpExpr:
                expr OR binaryOpOptions expr     { $$ = newLogBinaryOpExpr("or", $3, $1, $4)     }
        |       expr AND binaryOpOptions expr    { $$ = newLogBinaryOpExpr("and", $3, $1, $4)    }
        |       expr UNLESS binaryOpOptions expr { $$ = newLogBinaryOpExpr("unless", $3, $1, $4) }
        |       expr ADD binaryOpOptions expr    { $$ = newLogBinaryOpExpr("+", $3, $1, $4)      }
        |       expr SUB binaryOpOptions expr    { $$ = newLogBinaryOpExpr("-", $3, $1, $4)      }
        |       expr MUL binaryOpOptions expr    { $$ = newLogBinaryOpExpr("*", $3, $1, $4)      }
        |       expr DIV binaryOpOptions expr    { $$ = newLogBinaryOpExpr("/", $3, $1, $4)      }
        |       expr MOD binaryOpOptions expr    { $$ = newLogBinaryOpExpr("%", $3, $1, $4)      }
        |       expr POW binaryOpOptions expr    { $$ = newLogBinaryOpExpr("^", $3, $1, $4)      }
        |       expr CMP_EQ binaryOpOptions expr { $$ = newLogBinaryOpExpr("==", $3, $1, $4)     }
        |       expr NEQ binaryOpOptions expr    { $$ = newLogBinaryOpExpr("!=", $3, $1, $4)     }
        |       expr GT binaryOpOptions expr     { $$ = newLogBinaryOpExpr(">", $3, $1, $4)      }
        |       expr GTE binaryOpOptions expr    { $$ = newLogBinaryOpExpr(">=", $3, $1, $4)     }
        |       expr LT binaryOpOptions expr     { $$ = newLogBinaryOpExpr("<", $3, $1, $4)      }
        |       expr LTE binaryOpOptions expr    { $$ = newLogBinaryOpExpr("<=", $3, $1, $4)     }
        ;

logNumberExpr:
                NUMBER     { $$ = newLogNumberExpr($1, false) }
        |       ADD NUMBER { $$ = newLogNumberExpr($2, false) }
        |       SUB NUMBER { $$ = newLogNumberExpr($2, true)  }
        ;

binaryOpOptions:
                { $$ = BinaryOpOptions{} }
        |       BOOL { $$ = BinaryOpOptions{ ReturnBool: true } }
        |       binaryOpOptions ON OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, Labels: $4}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, Labels: $4, GroupingType: GroupLeftOption}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, Labels: $4, GroupingType: GroupLeftOption, IncludeLabels: $8}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, Labels: $4, GroupingType: GroupRightOption}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, Labels: $4, GroupingType: GroupRightOption, IncludeLabels: $8}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, GroupingType: GroupLeftOption}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, GroupingType: GroupLeftOption, IncludeLabels: $7}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, GroupingType: GroupRightOption}
                }
        |       binaryOpOptions ON OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.OnOption=OnOption{Enabled:true, GroupingType: GroupRightOption, IncludeLabels: $7}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, Labels: $4}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, Labels: $4, GroupingType: GroupLeftOption}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, Labels: $4, GroupingType: GroupLeftOption, IncludeLabels: $8}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, Labels: $4, GroupingType: GroupRightOption}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS labels CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, Labels: $4, GroupingType: GroupRightOption, IncludeLabels: $8}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, GroupingType: GroupLeftOption}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_LEFT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, GroupingType: GroupLeftOption, IncludeLabels: $7}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, GroupingType: GroupRightOption}
                }
        |       binaryOpOptions IGNORING OPEN_PARENTHESIS CLOSE_PARENTHESIS GROUP_RIGHT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS
                {
                   $$ = $1
                   $$.IgnoringOption=IgnoringOption{Enabled:true, GroupingType: GroupRightOption, IncludeLabels: $7}
                }
        ;

selector:
                OPEN_BRACE matchers CLOSE_BRACE { $$ = $2 }
        |       OPEN_BRACE matchers error       { $$ = $2 }
        |       OPEN_BRACE error CLOSE_BRACE    {         }
        ;

matchers:
                matcher                { $$ = []*labels.Matcher{$1} }
        |       matchers COMMA matcher { $$ = append($1, $3)        }
        ;

matcher:
                IDENTIFIER EQ STRING  { $$ = newLabelMatcher(labels.MatchEqual, $1, $3)     }
        |       IDENTIFIER NEQ STRING { $$ = newLabelMatcher(labels.MatchNotEqual, $1, $3)  }
        |       IDENTIFIER RE STRING  { $$ = newLabelMatcher(labels.MatchRegexp, $1, $3)    }
        |       IDENTIFIER NRE STRING { $$ = newLabelMatcher(labels.MatchNotRegexp, $1, $3) }
        ;

metricOp:
                COUNT_OVER_TIME    { $$ = RangeOpTypeCount       }
        |       RATE               { $$ = RangeOpTypeRate        }
        |       RATE_COUNTER       { $$ = RangeOpTypeRateCounter }
        |       BYTES_OVER_TIME    { $$ = RangeOpTypeBytes       }
        |       BYTES_RATE         { $$ = RangeOpTypeBytesRate   }
        |       AVG_OVER_TIME      { $$ = RangeOpTypeAvg         }
        |       SUM_OVER_TIME      { $$ = RangeOpTypeSum         }
        |       MIN_OVER_TIME      { $$ = RangeOpTypeMin         }
        |       MAX_OVER_TIME      { $$ = RangeOpTypeMax         }
        |       STDVAR_OVER_TIME   { $$ = RangeOpTypeStdvar      }
        |       STDDEV_OVER_TIME   { $$ = RangeOpTypeStddev      }
        |       QUANTILE_OVER_TIME { $$ = RangeOpTypeQuantile    }
        |       FIRST_OVER_TIME    { $$ = RangeOpTypeFirst       }
        |       LAST_OVER_TIME     { $$ = RangeOpTypeLast        }
        |       ABSENT_OVER_TIME   { $$ = RangeOpTypeAbsent      }
        |       SUM                { $$ = VectorOpTypeSum        }
        |       AVG                { $$ = VectorOpTypeAvg        }
        |       COUNT              { $$ = VectorOpTypeCount      }
        |       MAX                { $$ = VectorOpTypeMax        }
        |       MIN                { $$ = VectorOpTypeMin        }
        |       STDDEV             { $$ = VectorOpTypeStddev     }
        |       STDVAR             { $$ = VectorOpTypeStdvar     }
        |       BOTTOMK            { $$ = VectorOpTypeBottomK    }
        |       TOPK               { $$ = VectorOpTypeTopK       }
        |       VECTOR             { $$ = OpTypeVector           }
        ;

filter:
                PIPE_MATCH { $$ = "|~" }
        |       PIPE_EXACT { $$ = "|=" }
        |       NRE        { $$ = "!~" }
        |       NEQ        { $$ = "!=" }
        ;

comparisonOp:
                EQ  { $$ = "="  }
        |       NEQ { $$ = "!=" }
        |       RE  { $$ = "=~" }
        |       NRE { $$ = "!~" }
        |       GT  { $$ = ">"  }
        |       GTE { $$ = ">=" }
        |       LT  { $$ = "<"  }
        |       LTE { $$ = "<=" }
        ;

labels:
                IDENTIFIER              { $$ = []string{$1}   }
        |       labels COMMA IDENTIFIER { $$ = append($1, $3) }
        ;

grouping:
                BY OPEN_PARENTHESIS labels CLOSE_PARENTHESIS      { $$ = &grouping{without: false, groups: $3}  }
        |       WITHOUT OPEN_PARENTHESIS labels CLOSE_PARENTHESIS { $$ = &grouping{without: true, groups: $3}   }
        |       BY OPEN_PARENTHESIS CLOSE_PARENTHESIS             { $$ = &grouping{without: false, groups: nil} }
        |       WITHOUT OPEN_PARENTHESIS CLOSE_PARENTHESIS        { $$ = &grouping{without: true, groups: nil}  }
        ;
%%
