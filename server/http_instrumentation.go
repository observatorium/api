package server

import (
	"github.com/go-chi/chi/middleware"
	"github.com/observatorium/api/authentication"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"net/http"
	"strconv"
	"time"
)

// httpMetricsCollector is responsible for collecting HTTP metrics with extra tenant labels.
type httpMetricsCollector struct {
	requestCounter  *prometheus.CounterVec
	requestSize     *prometheus.SummaryVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
}

// newHTTPMetricsCollector creates a new httpMetricsCollector.
func newHTTPMetricsCollector(reg *prometheus.Registry, hardcodedLabels []string) httpMetricsCollector {
	m := httpMetricsCollector{
		requestCounter: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counter of HTTP requests.",
		},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		requestSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		responseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8),
			},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
	}
	return m
}

// instrumentedHandlerFactory is a factory for creating HTTP handlers instrumented by httpMetricsCollector.
type instrumentedHandlerFactory struct {
	metricsCollector httpMetricsCollector
}

// NewHandler creates a new instrumented HTTP handler with the given extra labels and calling the "next" handlers.
func (m instrumentedHandlerFactory) NewHandler(extraLabels prometheus.Labels, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		now := time.Now()
		next.ServeHTTP(rw, r)

		tenant, _ := authentication.GetTenantID(r.Context())
		m.metricsCollector.requestCounter.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Inc()

		size := computeApproximateRequestSize(r)
		m.metricsCollector.requestSize.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(float64(size))

		m.metricsCollector.requestDuration.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(time.Since(now).Seconds())

		m.metricsCollector.responseSize.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(float64(rw.BytesWritten()))
	}
}

// NewInstrumentedHandlerFactory creates a new instrumentedHandlerFactory.
func NewInstrumentedHandlerFactory(req *prometheus.Registry, hardcodedLabels []string) instrumentedHandlerFactory {
	return instrumentedHandlerFactory{
		metricsCollector: newHTTPMetricsCollector(req, hardcodedLabels),
	}
}

// Copied from https://github.com/prometheus/client_golang/blob/9075cdf61646b5adf54d3ba77a0e4f6c65cb4fd7/prometheus/promhttp/instrument_server.go#L350
func computeApproximateRequestSize(r *http.Request) int {
	s := 0
	if r.URL != nil {
		s += len(r.URL.String())
	}

	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return s
}
