package http

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/observatorium/observatorium/proxy"
)

const (
	ReadTimeout        = 15 * time.Minute
	WriteTimeout       = time.Minute
	lokiUpstreamPrefix = "/loki"
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
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

// ReadMiddleware adds a middleware for all read operations.
func ReadMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.readMiddlewares = append(h.readMiddlewares, m)
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
			read.Path = path.Join(read.Path, lokiUpstreamPrefix)
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-read"}),
			)

			proxyRead = &httputil.ReverseProxy{
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
			r.Handle("/api/v1/query", c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query"},
				proxyRead,
			))
			r.Handle("/api/v1/query_range", c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query_range"},
				proxyRead,
			))

			// Endpoints exposed by the querier and frontend
			// See https://grafana.com/docs/loki/latest/api/#microservices-mode
			addDatasourceLogAPIs(r, proxyRead, c)

			// Legacy APIs for Grafana <= 6
			addLegacyLogAPIS(r, proxyRead, c)
		})
	}

	if tail != nil {
		var tailRead http.Handler
		{
			tail.Path = path.Join(tail.Path, lokiUpstreamPrefix)
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(tail),
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
			r.Handle("/api/v1/tail", c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "tail"},
				tailRead,
			))

			// Legacy APIs for Grafana <= 6
			r.Handle("/api/prom/tail", c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "tail"},
				tailRead,
			))
		})
	}

	if write != nil {
		var proxyWrite http.Handler
		{
			write.Path = path.Join(write.Path, lokiUpstreamPrefix)
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(write),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-write"}),
			)

			proxyWrite = &httputil.ReverseProxy{
				Director: middlewares,
				ErrorLog: proxy.Logger(c.logger),
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout: WriteTimeout,
					}).DialContext,
				},
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			r.Handle("/api/v1/push", c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "push"},
				proxyWrite,
			))
		})
	}

	return r
}

func addDatasourceLogAPIs(r chi.Router, proxyRead http.Handler, c *handlerConfiguration) {
	// Undocumented but present in querier and query-frontend
	// see https://github.com/grafana/loki/blob/v1.6.1/pkg/loki/modules.go#L333
	r.Handle("/api/v1/label", c.instrument.NewHandler(
		prometheus.Labels{"group": "logsv1", "handler": "label"},
		proxyRead,
	))
	r.Handle("/api/v1/labels", c.instrument.NewHandler(
		prometheus.Labels{"group": "logsv1", "handler": "labels"},
		proxyRead,
	))
	r.Handle("/api/v1/label/{name}/values", c.instrument.NewHandler(
		prometheus.Labels{"group": "logsv1", "handler": "label/values"},
		proxyRead,
	))
}

func addLegacyLogAPIS(r chi.Router, proxyRead http.Handler, c *handlerConfiguration) {
	r.Handle("/api/prom/query", c.instrument.NewHandler(
		prometheus.Labels{"group": "logsv1", "handler": "query"},
		proxyRead,
	))
	r.Handle("/api/prom/label", c.instrument.NewHandler(
		prometheus.Labels{"group": "logsv1", "handler": "label"},
		proxyRead,
	))
	r.Handle("/api/prom/label/{name}/values", c.instrument.NewHandler(
		prometheus.Labels{"group": "logsv1", "handler": "label/values"},
		proxyRead,
	))
}
