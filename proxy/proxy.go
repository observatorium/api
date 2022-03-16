package proxy

import (
	"context"
	stdlog "log"
	"net/http"
	"net/url"
	"path"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

type contextKey string

const (
	prefixKey contextKey = "prefix"

	PrefixHeader string = "X-Forwarded-Prefix"
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

func MiddlewareSetPrefixHeader() Middleware {
	return func(r *http.Request) {
		prefix, ok := getPrefix(r.Context())
		if !ok {
			return
		}

		// Do not override the prefix header if it is already set.
		if r.Header.Get(PrefixHeader) != "" {
			return
		}

		r.Header.Set(PrefixHeader, prefix)
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

func getPrefix(ctx context.Context) (string, bool) {
	value := ctx.Value(prefixKey)
	prefix, ok := value.(string)

	return prefix, ok
}

// WithPrefix adds the provided prefix to the request context.
func WithPrefix(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), prefixKey, prefix),
		))
	})
}
