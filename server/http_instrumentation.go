package server

import (
	"github.com/go-chi/chi/middleware"
	"github.com/observatorium/api/authentication"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"net/http"
	"time"
)

// HTTPMetricsCollector is responsible for collecting HTTP metrics with an extra tenant labels.
type HTTPMetricsCollector struct {
	RequestCounter  *prometheus.CounterVec
	RequestSize     *prometheus.SummaryVec
	RequestDuration *prometheus.HistogramVec
	ResponseSize    *prometheus.HistogramVec
}

// NewHTTPMetricsCollector creates a new HTTPMetricsCollector.
func NewHTTPMetricsCollector(reg *prometheus.Registry, hardcodedLabels []string) HTTPMetricsCollector {
	m := HTTPMetricsCollector{
		RequestCounter: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counter of HTTP requests.",
		},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		RequestSize: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		ResponseSize: prometheus.NewHistogramVec(
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

// InstrumentedHandlerFactory is a factory for creating HTTP handlers instrumented by HTTPMetricsCollector.
type InstrumentedHandlerFactory struct {
	metricsCollector HTTPMetricsCollector
}

// NewHandler creates a new instrumented HTTP handler with the given extra labels and calling the "next" handlers.
func (m InstrumentedHandlerFactory) NewHandler(extraLabels prometheus.Labels, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		now := time.Now()
		next.ServeHTTP(rw, r)

		tenant, _ := authentication.GetTenantID(r.Context())
		m.metricsCollector.RequestCounter.MustCurryWith(extraLabels).WithLabelValues(http.StatusText(rw.Status()), r.Method, tenant).Inc()

		size := computeApproximateRequestSize(r)
		m.metricsCollector.RequestSize.MustCurryWith(extraLabels).WithLabelValues(http.StatusText(rw.Status()), r.Method, tenant).Observe(float64(size))

		m.metricsCollector.RequestDuration.MustCurryWith(extraLabels).WithLabelValues(http.StatusText(rw.Status()), r.Method, tenant).Observe(time.Since(now).Seconds())

		m.metricsCollector.ResponseSize.MustCurryWith(extraLabels).WithLabelValues(http.StatusText(rw.Status()), r.Method, tenant).Observe(float64(rw.BytesWritten()))
	}
}

// NewInstrumentedHandlerFactory creates a new InstrumentedHandlerFactory.
func NewInstrumentedHandlerFactory(req *prometheus.Registry, hardcodedLabels []string) InstrumentedHandlerFactory {
	return InstrumentedHandlerFactory{
		metricsCollector: NewHTTPMetricsCollector(req, hardcodedLabels),
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
