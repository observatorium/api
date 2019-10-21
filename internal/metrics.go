package internal

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	requestCounter  *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
}

func NewMetrics(r prometheus.Registerer) *Metrics {
	m := &Metrics{
		requestCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Counter of HTTP requests.",
			},
			[]string{"handler", "code"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 3, 8, 20, 60, 120},
			},
			[]string{"handler"},
		),
		responseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8),
			},
			[]string{"handler"},
		),
	}

	if r != nil {
		r.MustRegister(m.requestCounter, m.requestDuration, m.responseSize)
	}

	return m
}

func (m *Metrics) InstrumentHandler(handlerName string, handler http.Handler) http.HandlerFunc {
	handlerLabel := prometheus.Labels{"handler": handlerName}

	return promhttp.InstrumentHandlerCounter(m.requestCounter.MustCurryWith(handlerLabel),
		promhttp.InstrumentHandlerDuration(m.requestDuration.MustCurryWith(handlerLabel),
			promhttp.InstrumentHandlerResponseSize(m.responseSize.MustCurryWith(handlerLabel),
				handler,
			),
		),
	)
}
