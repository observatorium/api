package legacy

import (
	stdtls "crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/server"
	"github.com/observatorium/api/tls"
)

const (
	QueryRoute      = "/api/v1/query"
	QueryRangeRoute = "/api/v1/query_range"

	dialTimeout = 30 * time.Second // Set as in http.DefaultTransport
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
	spanRoutePrefix  string
	queryMiddlewares []func(http.Handler) http.Handler
	uiMiddlewares    []func(http.Handler) http.Handler
	labelParser      func(r *http.Request) prometheus.Labels
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

// WithGlobalMiddleware adds a middleware for all operations.
func WithGlobalMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.uiMiddlewares = append(h.uiMiddlewares, m...)
		h.queryMiddlewares = append(h.queryMiddlewares, m...)
	}
}

// WithLabelParser adds a custom label parser to the handler.
// The label parser is used to parse prometheus.Labels from the request.
func WithLabelParser(labelParser func(r *http.Request) prometheus.Labels) HandlerOption {
	return func(h *handlerConfiguration) {
		h.labelParser = labelParser
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(_ prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

func NewHandler(url *url.URL, upstreamCA []byte, upstreamCert *stdtls.Certificate, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, opt := range opts {
		opt(c)
	}

	r := chi.NewRouter()
	r.Use(server.InstrumentationMiddleware(c.labelParser))
	r.Use(func(handler http.Handler) http.Handler {
		return c.instrument.NewHandler(nil, handler)
	})

	var legacyProxy http.Handler
	{
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(url),
			proxy.MiddlewareLogger(c.logger),
			proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricslegacy-read"}),
		)

		t := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: dialTimeout,
			}).DialContext,
			TLSClientConfig: tls.NewClientConfig(upstreamCA, upstreamCert),
		}

		legacyProxy = &httputil.ReverseProxy{
			Director:  middlewares,
			ErrorLog:  proxy.Logger(c.logger),
			Transport: otelhttp.NewTransport(t),
		}
	}

	r.Group(func(r chi.Router) {
		r.Use(c.queryMiddlewares...)
		r.Handle(QueryRoute, otelhttp.WithRouteTag(c.spanRoutePrefix+QueryRoute, legacyProxy))
		r.Handle(QueryRangeRoute, otelhttp.WithRouteTag(c.spanRoutePrefix+QueryRangeRoute, legacyProxy))
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
