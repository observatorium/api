package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/log"
	"github.com/observatorium/api/authentication"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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
	m := httpMetricsCollector{
		hardcodedLabels: hardcodedLabels,
		requestCounter: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counter of HTTP requests.",
		},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		requestSize: promauto.With(reg).NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		requestDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			append(hardcodedLabels, "code", "method", "tenant"),
		),
		responseSize: promauto.With(reg).NewHistogramVec(
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
	logger           log.Logger
}

func (m instrumentedHandlerFactory) InitializeMetrics(labels prometheus.Labels) {
	m.metricsCollector.initializeMetrics(labels)
}

// NewHandler creates a new instrumented HTTP handler with the given extra labels and calling the "next" handlers.
func (m instrumentedHandlerFactory) NewHandler(_ prometheus.Labels, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		extraLabels := prometheus.Labels{"group": "unknown", "handler": "unknown"}
		r = r.WithContext(context.WithValue(r.Context(), ExtraLabelContextKey, extraLabels))

		rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		now := time.Now()
		next.ServeHTTP(rw, r)
		latency := time.Since(now)

		// if extra labels are provided on the context, merge them
		m.logger.Log("label from map", fmt.Sprintf("%s", extraLabels))
		if labels := r.Context().Value(ExtraLabelContextKey); labels != nil {
			ctxLabels := labels.(prometheus.Labels)
			for k, v := range ctxLabels {
				extraLabels[k] = v
			}
			m.logger.Log("extraLabels from context", fmt.Sprintf("%s", extraLabels))
		}
		m.logger.Log("extraLabels", fmt.Sprintf("%s", extraLabels))

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
			Observe(latency.Seconds())

		m.metricsCollector.responseSize.
			MustCurryWith(extraLabels).
			WithLabelValues(strconv.Itoa(rw.Status()), r.Method, tenant).
			Observe(float64(rw.BytesWritten()))
	}
}

// NewInstrumentedHandlerFactory creates a new instrumentedHandlerFactory.
func NewInstrumentedHandlerFactory(req *prometheus.Registry, hardcodedLabels []string, logger log.Logger) instrumentedHandlerFactory {
	return instrumentedHandlerFactory{
		metricsCollector: newHTTPMetricsCollector(req, hardcodedLabels),
		logger:           logger,
	}
}

type contextKey string

// ExtraLabelContextKey is the key for the extra labels in the request context.
const ExtraLabelContextKey contextKey = "extraLabels"

func InjectLabelsCtx(logger log.Logger, labels prometheus.Labels, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extraLabels := r.Context().Value(ExtraLabelContextKey).(prometheus.Labels)
		for k, v := range labels {
			extraLabels[k] = v
		}
		r = r.WithContext(context.WithValue(r.Context(), ExtraLabelContextKey, extraLabels))
		//newCtx := context.WithValue(r.Context(), ExtraLabelContextKey, labels)
		//logger.Log("extraLabels from inject", fmt.Sprintf("%s", labels))
		//if labels := newCtx.Value(ExtraLabelContextKey); labels != nil {
		//	ctxLabels := labels.(prometheus.Labels)
		//	logger.Log("extraLabels from context at inject", fmt.Sprintf("%s", ctxLabels))
		//}
		handler.ServeHTTP(w, r)
		//if labels := newCtx.Value(ExtraLabelContextKey); labels != nil {
		//	ctxLabels := labels.(prometheus.Labels)
		//	logger.Log("extraLabels from context after serving", fmt.Sprintf("%s", ctxLabels))
		//}
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
