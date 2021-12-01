//nolint:funlen
package http

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
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

// WithJaegerQueryV3 adds a custom Jaeger query for the handler to use.
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
			level.Debug(c.logger).Log("msg", "Configuring upstream Jaeger query v3", "queryv3", read)
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-read"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: ReadTimeout,
				}).DialContext,
			}

			proxyRead = &httputil.ReverseProxy{
				Director:     middlewares,
				ErrorLog:     proxy.Logger(c.logger),
				Transport:    otelhttp.NewTransport(t),
				ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {},
			}

			// @@@ TODO REMOVE
			proxyRead.(*httputil.ReverseProxy).ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
				level.Info(c.logger).Log("msg", "@@@ ecs http: proxy error", "err", err,
					"requestwas", fmt.Sprintf("%#v", r),
					"url", r.URL.String())
				rw.WriteHeader(http.StatusBadGateway)
			}

		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			const (
				queryRoute      = "/api/v3/traces"
				servicesRoute   = "/api/v3/services"
				operationsRoute = "/api/v3/operations"
			)
			r.Handle(queryRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query"}, proxyRead))
			// @@@,
			// otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, proxyRead),
			//))
			r.Handle(servicesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query_range"}, proxyRead))
			// ,
			// otelhttp.WithRouteTag(c.spanRoutePrefix+servicesRoute, proxyRead),
			// ))
			r.Handle(operationsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query_range"}, proxyRead))
			//,
			//otelhttp.WithRouteTag(c.spanRoutePrefix+operationsRoute, proxyRead),
			//))
		})
	}

	if write != nil {
		var proxyWrite http.Handler
		{
			level.Debug(c.logger).Log("msg", "Configuring upstream otel collector", "otel", write)
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(write),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-write"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: WriteTimeout,
				}).DialContext,
			}

			proxyWrite = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			const zipkinRoute = "/v1/trace"
			r.Handle(zipkinRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "tracingv1", "handler": "otel"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+zipkinRoute, proxyWrite),
			))
		})
	}

	return r
}
