package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/middleware"
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
}

// newHTTPMetricsCollector creates a new httpMetricsCollector.
func newHTTPMetricsCollector(reg *prometheus.Registry) httpMetricsCollector {
	m := httpMetricsCollector{
		requestCounter: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counter of HTTP requests.",
		},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
		requestSize: promauto.With(reg).NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "http_request_size_bytes",
				Help: "Size of HTTP requests.",
			},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
		requestDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 2.5, 5, 8, 20, 60, 120},
			},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
		responseSize: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8),
			},
			[]string{"group", "handler", "code", "method", "tenant"},
		),
	}
	return m
}

// instrumentedHandlerFactory is a factory for creating HTTP handlers instrumented by httpMetricsCollector.
type instrumentedHandlerFactory struct {
	metricsCollector httpMetricsCollector
}

// NewHandler creates a new instrumented HTTP handler with the given extra labels and calling the "next" handlers.
// If the extraLabels are nil, they will be fetched from the context. To store them in the context see the functions
// WithHandlerLabel and WithGroupLabel.
func (m instrumentedHandlerFactory) NewHandler(extraLabels prometheus.Labels, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(extraLabels) == 0 {
			if labels := r.Context().Value(extraHandlerLabelsCtxKey); labels != nil {
				ctxLabels, ok := labels.(prometheus.Labels)
				if ok {
					extraLabels = ctxLabels
				}
			}
		}
		rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		now := time.Now()
		next.ServeHTTP(rw, r)

		tenant, _ := authentication.GetTenantID(r.Context())
		statusCode := strconv.Itoa(rw.Status())
		method := r.Method
		group, ok := extraLabels["group"]
		if !ok {
			group = "unknown"
		}
		handler, ok := extraLabels["handler"]
		if !ok {
			handler = "unknown"
		}
		size := computeApproximateRequestSize(r)

		m.metricsCollector.requestCounter.WithLabelValues(group, handler, statusCode, method, tenant).Inc()
		m.metricsCollector.requestSize.WithLabelValues(group, handler, statusCode, method, tenant).Observe(float64(size))
		m.metricsCollector.requestDuration.WithLabelValues(group, handler, statusCode, method, tenant).Observe(time.Since(now).Seconds())
		m.metricsCollector.responseSize.WithLabelValues(group, handler, statusCode, method, tenant).Observe(float64(rw.BytesWritten()))
	}
}

// NewInstrumentedHandlerFactory creates a new instrumentedHandlerFactory.
func NewInstrumentedHandlerFactory(req *prometheus.Registry) instrumentedHandlerFactory {
	return instrumentedHandlerFactory{
		metricsCollector: newHTTPMetricsCollector(req),
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

var extraHandlerLabelsCtxKey = struct{}{}

func extraHandlerLabelFromContext(ctx context.Context) prometheus.Labels {
	labels, ok := ctx.Value(extraHandlerLabelsCtxKey).(prometheus.Labels)
	if !ok {
		return nil
	}
	return labels
}

// WithHandlerLabel stores desired value for the "handler" label in the context. It will later be
// picked up by the HTTP instrumentation middleware and used in its metrics.
func WithHandlerLabel(value string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return extraHandlerLabel("handler", value, next)
	}
}

// WithGroupLabel stores desired value for the "group" label in the context. It will later be
// picked up by the HTTP instrumentation middleware and used in its metrics.
func WithGroupLabel(value string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return extraHandlerLabel("group", value, next)
	}
}

func extraHandlerLabel(name, value string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labels := extraHandlerLabelFromContext(r.Context())
		if labels != nil {
			next.ServeHTTP(w, r)
			return
		}
		labels[name] = value
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), extraHandlerLabelsCtxKey, labels)))
	})
}
