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

	"github.com/observatorium/observatorium/internal/proxy"
)

const (
	ReadTimeout  = 15 * time.Minute
	WriteTimeout = time.Minute
)

type handlerConfiguration struct {
	logger     log.Logger
	registry   *prometheus.Registry
	instrument handlerInstrumenter
}

// HandlerOption modifies the handler's configuration
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

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

// NewHandler creates the new metrics v1 handler
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
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-read"}),
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
		r.Handle("/api/v1/query", c.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "query"},
			proxyRead,
		))
		r.Handle("/api/v1/query_range", c.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "query_range"},
			proxyRead,
		))

		var uiProxy http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-ui"}),
			)

			uiProxy = &httputil.ReverseProxy{
				Director: middlewares,
			}
		}
		r.Mount("/", c.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "ui"},
			uiProxy,
		))
	}

	if write != nil {
		var proxyWrite http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(write),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-write"}),
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
		r.Handle("/write", c.instrument.NewHandler(
			prometheus.Labels{"group": "metricsv1", "handler": "write"},
			http.StripPrefix("/write",
				proxyWrite,
			),
		))
	}

	return r
}
