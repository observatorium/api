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
	ReadTimeout = 15 * time.Minute
)

type handlerConfiguration struct {
	logger     log.Logger
	registry   *prometheus.Registry
	instrument handlerInstrumenter
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
					Timeout: ReadTimeout,
				}).DialContext,
			},
		}
	}

	r.Handle("/query", c.instrument.NewHandler(
		prometheus.Labels{"group": "metricslegacy", "handler": "query"},
		legacyProxy,
	))
	r.Handle("/query_range", c.instrument.NewHandler(
		prometheus.Labels{"group": "metricslegacy", "handler": "query_range"},
		legacyProxy,
	))

	return r
}
