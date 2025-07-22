package v1

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/tls"
)

type handlerOptions struct {
	logger           log.Logger
	tenantHeader     string
	tlsOptions       *tls.UpstreamOptions
	readMiddlewares  []func(http.Handler) http.Handler
	writeMiddlewares []func(http.Handler) http.Handler
}

// HandlerOption is a function that configures the handler.
type HandlerOption func(*handlerOptions)

// WithLogger sets the logger for the handler.
func WithLogger(l log.Logger) HandlerOption {
	return func(o *handlerOptions) {
		o.logger = l
	}
}

// WithTenantHeader sets the tenant header for the handler.
func WithTenantHeader(h string) HandlerOption {
	return func(o *handlerOptions) {
		o.tenantHeader = h
	}
}

// WithUpstreamTLSOptions sets the upstream TLS options for the handler.
func WithUpstreamTLSOptions(opts *tls.UpstreamOptions) HandlerOption {
	return func(o *handlerOptions) {
		o.tlsOptions = opts
	}
}

// WithReadMiddleware adds a middleware for read operations.
func WithReadMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(o *handlerOptions) {
		o.readMiddlewares = append(o.readMiddlewares, m)
	}
}

// WithWriteMiddleware adds a middleware for write operations.
func WithWriteMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(o *handlerOptions) {
		o.writeMiddlewares = append(o.writeMiddlewares, m)
	}
}

// NewHandler creates a new handler for the probes API.
func NewHandler(downstream *url.URL, opts ...HandlerOption) (http.Handler, error) {
	options := &handlerOptions{
		logger: log.NewNopLogger(),
	}
	for _, o := range opts {
		o(options)
	}

	r := chi.NewRouter()
	proxy := httputil.NewSingleHostReverseProxy(downstream)

	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     options.tlsOptions.NewClientConfig(),
	}

	if options.tenantHeader != "" {
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			tenant, ok := authentication.GetTenant(req.Context())
			if !ok {
				level.Warn(options.logger).Log("msg", "could not find tenant in request context for proxy")
			} else {
				req.Header.Set(options.tenantHeader, tenant)
			}
		}
	}

	proxyHandler := http.HandlerFunc(proxy.ServeHTTP)

	r.Group(func(r chi.Router) {
		r.Use(options.readMiddlewares...)
		r.Get("/*", proxyHandler)
	})

	r.Group(func(r chi.Router) {
		r.Use(options.writeMiddlewares...)
		r.Post("/*", proxyHandler)
		r.Patch("/*", proxyHandler)
		r.Delete("/*", proxyHandler)
	})

	return r, nil
}
