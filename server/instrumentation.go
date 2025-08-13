package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// Logger returns a middleware to log HTTP requests.
func Logger(logger log.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			var query string
			if isQuery(r) {
				if storeBody(r) {
					// Store the body for logging.
					originalBody, err := io.ReadAll(r.Body)
					if err != nil {
						level.Error(logger).Log("msg", "error reading body", "err", err)
					}
					r.Body = io.NopCloser(bytes.NewBuffer(originalBody))
					if len(originalBody) > 0 {
						query = string(originalBody)
					}
				} else {
					query = r.URL.RawQuery
				}
			}

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			if strings.HasSuffix(r.URL.Path, "/receive") {
				// Skip logging for /receive endpoint.
				return
			}

			keyvals := []interface{}{
				"request", middleware.GetReqID(r.Context()),
				"proto", r.Proto,
				"method", r.Method,
				"status", ww.Status(),
				"content", r.Header.Get("Content-Type"),
				"path", r.URL.Path,
				"duration", time.Since(start),
				"bytes", ww.BytesWritten(),
			}

			if query != "" {
				keyvals = append(keyvals, "query", query)
				level.Debug(logger).Log(keyvals...)
				return
			}

			if strings.Contains(r.URL.Path, "/receive") {
				return
			}

			if ww.Status()/100 == 5 {
				level.Warn(logger).Log(keyvals...)
				return
			}
			level.Debug(logger).Log(keyvals...)
		})
	}
}

func isQuery(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}

	if strings.HasSuffix(r.URL.Path, "/query") || strings.HasSuffix(r.URL.Path, "/query_range") {
		return true
	}
	return false
}

func storeBody(r *http.Request) bool {
	if r == nil || r.Body == nil || r.Method != http.MethodPost {
		return false
	}
	return true
}
