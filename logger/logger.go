package logger

import (
	"os"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

const (
	LogFormatLogfmt = "logfmt"
	LogFormatJSON   = "json"
)

func NewLogger(logLevel, logFormat, debugName string) log.Logger {
	var (
		logger log.Logger
		lvl    level.Option
	)

	switch logLevel {
	case "error":
		lvl = level.AllowError()
	case "warn":
		lvl = level.AllowWarn()
	case "info":
		lvl = level.AllowInfo()
	case "debug":
		lvl = level.AllowDebug()
	default:
		panic("unexpected log level")
	}

	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	if logFormat == LogFormatJSON {
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
	}

	logger = level.NewFilter(logger, lvl)

	if debugName != "" {
		logger = log.With(logger, "name", debugName)
	}

	return log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
}
