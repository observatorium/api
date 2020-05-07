package proxy

import (
	stdlog "log"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultBufferCount is the default value for the maximum size of the buffer pool for the reverse proxy.
	DefaultBufferCount = 2 * 1024
	// DefaultBufferSizeBytes is the default value for the length of the buffers in the buffer pool for the reverse proxy.
	DefaultBufferSizeBytes = 32 * 1024
	// DefaultFlushInterval is the default value for the flush interval of reverse proxy to flush to the client while copying the response body.
	DefaultFlushInterval = time.Duration(-1)
)

type Middleware func(r *http.Request)

func Middlewares(middlewares ...Middleware) func(r *http.Request) {
	return func(r *http.Request) {
		for _, m := range middlewares {
			m(r)
		}
	}
}

func MiddlewareSetUpstream(upstream *url.URL) Middleware {
	return func(r *http.Request) {

		r.URL.Scheme = upstream.Scheme
		r.URL.Host = upstream.Host
	}
}

func MiddlewareLogger(logger log.Logger) Middleware {
	return func(r *http.Request) {
		rlogger := log.With(logger, "request", middleware.GetReqID(r.Context()))
		level.Debug(rlogger).Log("msg", "request to upstream", "url", r.URL.String())
	}
}

func MiddlewareMetrics(registry *prometheus.Registry, constLabels prometheus.Labels) Middleware {
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "http_proxy_requests_total",
		Help:        "Counter of proxy HTTP requests.",
		ConstLabels: constLabels,
	}, []string{"method"})

	registry.MustRegister(requests)

	return func(r *http.Request) {
		requests.With(prometheus.Labels{"method": r.Method}).Inc()
	}
}

func Logger(logger log.Logger) *stdlog.Logger {
	return stdlog.New(log.NewStdlibAdapter(level.Warn(logger)), "", stdlog.Lshortfile)
}
