package proxy

import (
	stdlog "log"
	"net/http"
	"net/url"
	"path"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
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
		r.URL.Path = path.Join(upstream.Path, r.URL.Path)
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
