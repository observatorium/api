//nolint:funlen
package http

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
	ReadTimeout  = 15 * time.Minute
	WriteTimeout = time.Minute
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
	spanRoutePrefix  string
	readMiddlewares  []func(http.Handler) http.Handler
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

// WithRegistry adds a custom Prometheus registry for the handler to use.
func WithRegistry(r *prometheus.Registry) HandlerOption {
	return func(h *handlerConfiguration) {
		h.registry = r
	}
}

// WithHandlerInstrumenter adds a custom HTTP handler instrument middleware for the handler to use.
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

// WithReadMiddleware adds a middleware for all read operations.
func WithReadMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.readMiddlewares = append(h.readMiddlewares, m)
	}
}

// WithWriteMiddleware adds a middleware for all write operations.
func WithWriteMiddleware(m func(http.Handler) http.Handler) HandlerOption {
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

func NewHandler(read, tail, write *url.URL, opts ...HandlerOption) http.Handler {
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
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-read"}),
			)

			proxyRead = &httputil.ReverseProxy{
				Director: middlewares,
				ErrorLog: proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(
					&http.Transport{
						DialContext: (&net.Dialer{
							Timeout: ReadTimeout,
						}).DialContext,
					},
				),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			const (
				queryRoute      = "/loki/api/v1/query"
				queryRangeRoute = "/loki/api/v1/query_range"
			)
			r.Handle(queryRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, proxyRead),
			))
			r.Handle(queryRangeRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query_range"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRangeRoute, proxyRead),
			))

			// Endpoints exposed by the querier and frontend
			// See https://grafana.com/docs/loki/latest/api/#microservices-mode

			// Undocumented but present in querier and query-frontend
			// see https://github.com/grafana/loki/blob/v1.6.1/pkg/loki/modules.go#L333
			const (
				labelRoute       = "/loki/api/v1/label"
				labelsRoute      = "/loki/api/v1/labels"
				labelValuesRoute = "/loki/api/v1/label/{name}/values"
				seriesRoute      = "/loki/api/v1/series"
			)
			r.Handle(labelRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelRoute, proxyRead),
			))
			r.Handle(labelsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "labels"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelsRoute, proxyRead),
			))
			r.Handle(labelValuesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label_values"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelValuesRoute, proxyRead),
			))
			r.Handle(seriesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "series"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+seriesRoute, proxyRead),
			))

			// Legacy APIs for Grafana <= 6
			const (
				promQueryRoute       = "/api/prom/query"
				promLabelRoute       = "/api/prom/label"
				promLabelValuesRoute = "/api/prom/label/{name}/values"
				promSeriesRoute      = "/api/prom/series"
			)
			r.Handle(promQueryRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promQueryRoute, proxyRead),
			))
			r.Handle(promLabelRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promLabelRoute, proxyRead),
			))
			r.Handle(promLabelValuesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label_values"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promLabelValuesRoute, proxyRead),
			))
			r.Handle(promSeriesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "series"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promSeriesRoute, proxyRead),
			))
		})
	}

	if tail != nil {
		var tailRead http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(tail),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-tail"}),
			)

			tailRead = &httputil.ReverseProxy{
				Director: middlewares,
				ErrorLog: proxy.Logger(c.logger),
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout: ReadTimeout,
					}).DialContext,
				},
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			const tailRoute = "/loki/api/v1/tail"
			r.Handle(tailRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "tail"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+tailRoute, tailRead),
			))

			// Legacy APIs for Grafana <= 6
			const promTailRoute = "/api/prom/tail"
			r.Handle(promTailRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "prom_tail"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promTailRoute, tailRead),
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
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-write"}),
			)

			proxyWrite = &httputil.ReverseProxy{
				Director: middlewares,
				ErrorLog: proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(
					&http.Transport{
						DialContext: (&net.Dialer{
							Timeout: ReadTimeout,
						}).DialContext,
					},
				),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			const pushRoute = "/loki/api/v1/push"
			r.Handle(pushRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "push"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+pushRoute, proxyWrite),
			))
		})
	}

	return r
}
