package v1

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
	readTimeout  = 15 * time.Minute
	writeTimeout = time.Minute
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
	spanRoutePrefix  string
	readMiddlewares  []func(http.Handler) http.Handler
	uiMiddlewares    []func(http.Handler) http.Handler
	writeMiddlewares []func(http.Handler) http.Handler
}

// HandlerOption modifies the handler's configuration.
type HandlerOption func(h *handlerConfiguration)

// Logger add a custom logger for the handler to use.
func Logger(logger log.Logger) HandlerOption {
	return func(h *handlerConfiguration) {
		h.logger = logger
	}
}

// Registry adds a custom Prometheus registry for the handler to use.
func Registry(r *prometheus.Registry) HandlerOption {
	return func(h *handlerConfiguration) {
		h.registry = r
	}
}

// HandlerInstrumenter adds a custom HTTP handler instrument middleware for the handler to use.
func HandlerInstrumenter(instrumenter handlerInstrumenter) HandlerOption {
	return func(h *handlerConfiguration) {
		h.instrument = instrumenter
	}
}

// SpanRoutePrefix adds a prefix before the value of route tag in tracing spans.
func SpanRoutePrefix(spanRoutePrefix string) HandlerOption {
	return func(h *handlerConfiguration) {
		h.spanRoutePrefix = spanRoutePrefix
	}
}

// ReadMiddleware adds a middleware for all read operations.
func ReadMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.readMiddlewares = append(h.readMiddlewares, m)
	}
}

// UIMiddleware adds a middleware for all ui operations.
func UIMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.uiMiddlewares = append(h.uiMiddlewares, m)
	}
}

// WriteMiddleware adds a middleware for all write operations.
func WriteMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.writeMiddlewares = append(h.writeMiddlewares, m)
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

// NewHandler creates the new metrics v1 handler.
func NewHandler(read, write *url.URL, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()

	if read != nil {
		var proxyRead http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-read"}),
			)

			proxyRead = &httputil.ReverseProxy{
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
			r.Use(c.readMiddlewares...)
			const (
				queryRoute      = "/api/v1/query"
				queryRangeRoute = "/api/v1/query_range"
			)

			r.Handle(queryRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "query"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, proxyRead),
			))
			r.Handle(queryRangeRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "query_range"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRangeRoute, proxyRead),
			))
		})

		var uiProxy http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-ui"}),
			)

			uiProxy = &httputil.ReverseProxy{
				Director:  middlewares,
				Transport: otelhttp.NewTransport(http.DefaultTransport),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.uiMiddlewares...)
			const uiRoute = "/"

			r.Mount(uiRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "ui"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+uiRoute, uiProxy),
			))
		})
	}

	if write != nil {
		var proxyWrite http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(write),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-write"}),
			)

			proxyWrite = &httputil.ReverseProxy{
				Director: middlewares,
				ErrorLog: proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(
					&http.Transport{
						DialContext: (&net.Dialer{
							Timeout: writeTimeout,
						}).DialContext,
					},
				),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			const receiveRoute = "/api/v1/receive"
			r.Handle(receiveRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "receive"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+receiveRoute, proxyWrite),
			))
		})
	}

	return r
}
