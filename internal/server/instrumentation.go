package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type instrumentationMiddleware struct {
	requestCounter  *prometheus.CounterVec
	requestSize     *prometheus.SummaryVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
}

func newInstrumentationMiddleware(r prometheus.Registerer) *instrumentationMiddleware {
	ins := &instrumentationMiddleware{
		requestCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Counter of HTTP requests.",
			},
			[]string{"code", "handler", "method"},
		),
		requestSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			[]string{"code", "handler", "method"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			[]string{"code", "handler", "method"},
		),
		responseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8), //nolint:gomnd
			},
			[]string{"code", "handler", "method"},
		),
	}

	if r != nil {
		r.MustRegister(ins.requestCounter, ins.requestDuration, ins.responseSize)
	}

	return ins
}

func (ins *instrumentationMiddleware) newHandler(handlerName string, handler http.Handler) http.HandlerFunc {
	handlerLabel := prometheus.Labels{"handler": handlerName}

	return promhttp.InstrumentHandlerCounter(ins.requestCounter.MustCurryWith(handlerLabel),
		promhttp.InstrumentHandlerRequestSize(ins.requestSize.MustCurryWith(handlerLabel),
			promhttp.InstrumentHandlerDuration(ins.requestDuration.MustCurryWith(handlerLabel),
				promhttp.InstrumentHandlerResponseSize(ins.responseSize.MustCurryWith(handlerLabel),
					handler,
				),
			),
		),
	)
}
