package v1

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
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

// NewV2APIHandler creates a trace query handler for Jaeger V2 HTTP queries
func NewV2APIHandler(read *url.URL, opts ...HandlerOption) http.Handler {
	fmt.Printf("@@@ ecs REACHED NewV2APIHandler()\n")
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()

	var proxyRead http.Handler
	{
		level.Debug(c.logger).Log("msg", "Configuring upstream Jaeger query v2", "queryv2", read)
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(read),
			proxy.MiddlewareSetPrefixHeader(),
			proxy.MiddlewareLogger(c.logger),
			// @@@ TODO restore? proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-read"}),
		)

		t := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ReadTimeout,
			}).DialContext,
		}

		fmt.Printf("@@@ ecs constructing reverse proxy for traces\n")
		proxyRead = &httputil.ReverseProxy{
			Director:     middlewares,
			ErrorLog:     proxy.Logger(c.logger),
			Transport:    otelhttp.NewTransport(t),
			ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {},
		}
	}
	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		const (
			queryRoute      = "/api/traces"
			servicesRoute   = "/api/services"
			operationsRoute = "/api/operations"
		)
		r.Handle(queryRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1", "handler": "query"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, proxyRead)))
		r.Handle(servicesRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1", "handler": "query_range"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+servicesRoute, proxyRead)))
		r.Handle(operationsRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1", "handler": "query_range"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+operationsRoute, proxyRead)))
	})

	return r
}

// NewUIHandler creates a trace handler for Jaeger UI
func NewUIHandler(read *url.URL, opts ...HandlerOption) http.Handler {
	fmt.Printf("@@@ ecs REACHED NewUIHandler()\n")
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()

	var proxyRead http.Handler
	{
		level.Debug(c.logger).Log("msg", "Configuring upstream Jaeger UI", "ui", read)
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(read),
			proxy.MiddlewareSetPrefixHeader(),
			proxy.MiddlewareLogger(c.logger),
			// @@@ TODO restore? proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-read"}),
		)

		t := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ReadTimeout,
			}).DialContext,
		}

		proxyRead = &httputil.ReverseProxy{
			Director:  middlewares,
			ErrorLog:  proxy.Logger(c.logger),
			Transport: otelhttp.NewTransport(t),
			ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {
				fmt.Printf("@@@ ecs in NewUIHandler anon ErrorHandler for request %#v\n", r)
			},
		}
	}
	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		/*
			const (
				searchRoute  = "/search"
				staticRoute  = "/static/*"
				faviconRoute = "/favicon.ico"
			)
			r.Handle(searchRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "tracesv1ui", "handler": "search"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+searchRoute, proxyRead)))
			r.Handle(staticRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "tracesv1ui", "handler": "static"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+staticRoute, proxyRead)))
			r.Handle(faviconRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "tracesv1ui", "handler": "static"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+faviconRoute, proxyRead)))
		*/
		r.Handle("/*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1ui", "handler": "search"},
			proxyRead))
	})

	return r
}
