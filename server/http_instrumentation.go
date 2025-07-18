package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/observatorium/api/authentication"
)

// httpMetricsCollector is responsible for collecting HTTP metrics with extra tenant labels.
type httpMetricsCollector struct {
	requestCounter  *prometheus.CounterVec
	requestSize     *prometheus.SummaryVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
	hardcodedLabels []string
}

func (m httpMetricsCollector) initializeMetrics(labels prometheus.Labels) {
	// Check if all hardcodedLabels are present in labels
	for _, hardcodedLabel := range m.hardcodedLabels {
		if _, ok := labels[hardcodedLabel]; !ok {
			panic("missing hardcoded label: " + hardcodedLabel)
		}
	}

	m.requestCounter.MustCurryWith(labels).WithLabelValues("", "", "")
	m.requestSize.MustCurryWith(labels).WithLabelValues("", "", "")
	m.requestDuration.MustCurryWith(labels).WithLabelValues("", "", "")
	m.responseSize.MustCurryWith(labels).WithLabelValues("", "", "")
}

// newHTTPMetricsCollector creates a new httpMetricsCollector.
func newHTTPMetricsCollector(reg *prometheus.Registry, hardcodedLabels []string) httpMetricsCollector {
	metricLabels := append(hardcodedLabels, "code", "method", "tenant")

	m := httpMetricsCollector{
		hardcodedLabels: hardcodedLabels,
		requestCounter: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counter of HTTP requests.",
		},
			metricLabels,
		),
		requestSize: promauto.With(reg).NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			metricLabels,
		),
		requestDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			metricLabels,
		),
		responseSize: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8),
			},
			metricLabels,
		),
	}
	return m
}

// instrumentedHandlerFactory is a factory for creating HTTP handlers instrumented by httpMetricsCollector.
type instrumentedHandlerFactory struct {
	metricsCollector httpMetricsCollector
}

func (m instrumentedHandlerFactory) InitializeMetrics(labels prometheus.Labels) {
	m.metricsCollector.initializeMetrics(labels)
}

// NewHandler creates a new instrumented HTTP handler with the given extra labels and calling the "next" handlers.
func (m instrumentedHandlerFactory) NewHandler(extraLabels prometheus.Labels, next http.Handler) http.HandlerFunc {
	// Default group and handler to "unknown" if no extra labels are provided as a parameter.
	if extraLabels == nil {
		extraLabels = prometheus.Labels{"group": "unknown", "handler": "unknown"}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		requestLabels := make(prometheus.Labels, len(extraLabels))
		for k, v := range extraLabels {
			requestLabels[k] = v
		}

		r = r.WithContext(context.WithValue(r.Context(), ExtraLabelContextKey, requestLabels))

		rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		now := time.Now()
		next.ServeHTTP(rw, r)
		latency := time.Since(now)

		// if different extra labels come back through the context after serving the request, merge them.
		if labels := r.Context().Value(ExtraLabelContextKey); labels != nil {
			ctxLabels := labels.(prometheus.Labels)
			for k, v := range ctxLabels {
				requestLabels[k] = v
			}
		}

		tenant, _ := authentication.GetTenantID(r.Context())
		m.metricsCollector.requestCounter.
			MustCurryWith(requestLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Inc()

		size := computeApproximateRequestSize(r)
		m.metricsCollector.requestSize.
			MustCurryWith(requestLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(float64(size))

		m.metricsCollector.requestDuration.
			MustCurryWith(requestLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(latency.Seconds())

		m.metricsCollector.responseSize.
			MustCurryWith(requestLabels).
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

type contextKey string

// ExtraLabelContextKey is the key for the extra labels in the request context.
const ExtraLabelContextKey contextKey = "extraLabels"

func InjectLabelsCtx(labels prometheus.Labels, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extraLabels, ok := r.Context().Value(ExtraLabelContextKey).(prometheus.Labels)
		if !ok {
			extraLabels = prometheus.Labels{}
		}
		if extraLabels != nil {
			for k, v := range labels {
				extraLabels[k] = v
			}
			r = r.WithContext(context.WithValue(r.Context(), ExtraLabelContextKey, extraLabels))
		}
		handler.ServeHTTP(w, r)
	})
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
