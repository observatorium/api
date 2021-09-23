package legacy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/proxy"
)

const (
	readTimeout = 15 * time.Minute
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
	spanRoutePrefix  string
	queryMiddlewares []func(http.Handler) http.Handler
	uiMiddlewares    []func(http.Handler) http.Handler
}

type HandlerOption func(h *handlerConfiguration)

func WithLogger(logger log.Logger) HandlerOption {
	return func(h *handlerConfiguration) {
		h.logger = logger
	}
}

func WithRegistry(r *prometheus.Registry) HandlerOption {
	return func(h *handlerConfiguration) {
		h.registry = r
	}
}

func WithHandlerInstrumenter(instrumenter handlerInstrumenter) HandlerOption {
	return func(h *handlerConfiguration) {
		h.instrument = instrumenter
	}
}

// WithSpanRoutePrefix adds a prefix before the value of route tag in tracing spans.
func WithSpanRoutePrefix(spanRoutePrefix string) HandlerOption {
	return func(h *handlerConfiguration) {
		h.spanRoutePrefix = spanRoutePrefix
	}
}

// WithQueryMiddleware adds a middleware for all query operations.
func WithQueryMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.queryMiddlewares = append(h.queryMiddlewares, m)
	}
}

// WithUIMiddleware adds a middleware for all other operations than read, query and write operations.
func WithUIMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.uiMiddlewares = append(h.uiMiddlewares, m)
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(_ prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

func NewHandler(url *url.URL, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, opt := range opts {
		opt(c)
	}

	r := chi.NewRouter()

	var legacyProxy http.Handler
	{
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(url),
			proxy.MiddlewareLogger(c.logger),
			proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricslegacy-read"}),
		)

		legacyProxy = &httputil.ReverseProxy{
			Director: middlewares,
			ErrorLog: proxy.Logger(c.logger),
			Transport: otelhttp.NewTransport(
				&http.Transport{
					DialContext: (&net.Dialer{
						Timeout: readTimeout,
					}).DialContext,
				},
			),
		}
	}

	r.Group(func(r chi.Router) {
		r.Use(c.queryMiddlewares...)
		const (
			queryRoute      = "/api/v1/query"
			queryRangeRoute = "/api/v1/query_range"
		)

		r.Handle(queryRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "metricslegacy", "handler": "query"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, legacyProxy),
		))
		r.Handle(queryRangeRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "metricslegacy", "handler": "query_range"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+queryRangeRoute, legacyProxy),
		))
	})

	r.Group(func(r chi.Router) {
		r.Use(c.uiMiddlewares...)

		r.HandleFunc("/graph", func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = "/api/metrics/v1/graph"
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
		})
	})

	return r
}
