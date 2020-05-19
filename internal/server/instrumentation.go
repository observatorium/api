package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TODO(metalmatze): Move this file to github.com/metalmatze/signal. It's applicable outside this project as well.

type instrumentationMiddleware struct {
	requestCounter  *prometheus.CounterVec
	requestSize     *prometheus.SummaryVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
}

// HandlerInstrumenter can instrument handlers.
type HandlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

// NewInstrumentationMiddleware creates a new middleware that observes some metrics for HTTP handlers.
func NewInstrumentationMiddleware(r prometheus.Registerer) HandlerInstrumenter {
	labels := []string{"code", "method", "group", "handler"}
	ins := &instrumentationMiddleware{
		requestCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Counter of HTTP requests.",
			},
			labels,
		),
		requestSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			labels,
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			labels,
		),
		responseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8), //nolint:gomnd
			},
			labels,
		),
	}

	if r != nil {
		r.MustRegister(
			ins.requestCounter,
			ins.requestSize,
			ins.requestDuration,
			ins.responseSize,
		)
	}

	return ins
}

// NewHandler wraps a HTTP handler with some metrics for HTTP handlers.
func (ins *instrumentationMiddleware) NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return promhttp.InstrumentHandlerCounter(ins.requestCounter.MustCurryWith(labels),
		promhttp.InstrumentHandlerRequestSize(ins.requestSize.MustCurryWith(labels),
			promhttp.InstrumentHandlerDuration(ins.requestDuration.MustCurryWith(labels),
				promhttp.InstrumentHandlerResponseSize(ins.responseSize.MustCurryWith(labels),
					handler,
				),
			),
		),
	)
}

// Logger returns a middleware to log HTTP requests.
func Logger(logger log.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

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

			if ww.Status()/100 == 5 {
				level.Warn(logger).Log(keyvals...)
				return
			}
			level.Debug(logger).Log(keyvals...)
		})
	}
}
