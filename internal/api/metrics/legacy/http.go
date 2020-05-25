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

	"github.com/observatorium/observatorium/internal/proxy"
)

const (
	readTimeout = 15 * time.Minute
)

type handlerConfiguration struct {
	logger          log.Logger
	registry        *prometheus.Registry
	instrument      handlerInstrumenter
	readMiddlewares []func(http.Handler) http.Handler
}

type HandlerOption func(h *handlerConfiguration)

func Logger(logger log.Logger) HandlerOption {
	return func(h *handlerConfiguration) {
		h.logger = logger
	}
}

func Registry(r *prometheus.Registry) HandlerOption {
	return func(h *handlerConfiguration) {
		h.registry = r
	}
}

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

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc {
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
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: readTimeout,
				}).DialContext,
			},
		}
	}

	r.Use(c.readMiddlewares...)
	r.Handle("/api/v1/query", c.instrument.NewHandler(
		prometheus.Labels{"group": "metricslegacy", "handler": "query"},
		legacyProxy,
	))
	r.Handle("/api/v1/query_range", c.instrument.NewHandler(
		prometheus.Labels{"group": "metricslegacy", "handler": "query_range"},
		legacyProxy,
	))

	r.HandleFunc("/graph", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/api/metrics/v1/graph"
		http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
	})

	return r
}
