package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/tls"
)

type handlerOptions struct {
	logger              log.Logger
	tenantHeader        string
	tlsOptions          *tls.UpstreamOptions
	dialTimeout         time.Duration
	keepAliveTimeout    time.Duration
	tlsHandshakeTimeout time.Duration
	readMiddlewares     []func(http.Handler) http.Handler
	writeMiddlewares    []func(http.Handler) http.Handler
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

// WithDialTimeout sets the dial timeout for upstream connections.
func WithDialTimeout(timeout time.Duration) HandlerOption {
	return func(o *handlerOptions) {
		o.dialTimeout = timeout
	}
}

// WithKeepAliveTimeout sets the keep-alive timeout for upstream connections.
func WithKeepAliveTimeout(timeout time.Duration) HandlerOption {
	return func(o *handlerOptions) {
		o.keepAliveTimeout = timeout
	}
}

// WithTLSHandshakeTimeout sets the TLS handshake timeout for upstream connections.
func WithTLSHandshakeTimeout(timeout time.Duration) HandlerOption {
	return func(o *handlerOptions) {
		o.tlsHandshakeTimeout = timeout
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
		logger:              log.NewNopLogger(),
		dialTimeout:         30 * time.Second,
		keepAliveTimeout:    30 * time.Second,
		tlsHandshakeTimeout: 10 * time.Second,
	}
	for _, o := range opts {
		o(options)
	}

	r := chi.NewRouter()
	proxy := httputil.NewSingleHostReverseProxy(downstream)

	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   options.dialTimeout,
			KeepAlive: options.keepAliveTimeout,
		}).DialContext,
		TLSHandshakeTimeout: options.tlsHandshakeTimeout,
		TLSClientConfig:     options.tlsOptions.NewClientConfig(),
	}

	if options.tenantHeader != "" {
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			tenant, ok := authentication.GetTenant(req.Context())
			if !ok {
				level.Warn(options.logger).Log("msg", "could not find tenant in request context for proxy")
				return
			}

			// Set tenant header
			req.Header.Set(options.tenantHeader, tenant)

			// Inject tenant label into POST request body.
			if req.Method == http.MethodPost {
				if req.Body == nil {
					return // Nothing to do
				}

				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					level.Error(options.logger).Log("msg", "failed to read request body", "err", err)
					req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body
					return
				}
				// Restore body since it's been consumed
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

				var payload map[string]interface{}
				if err := json.Unmarshal(bodyBytes, &payload); err != nil {
					level.Warn(options.logger).Log("msg", "failed to unmarshal JSON body, forwarding unmodified", "err", err)
					return
				}

				labels, ok := payload["labels"].(map[string]interface{})
				if !ok {
					labels = make(map[string]interface{})
				}

				labels["tenant"] = tenant
				payload["labels"] = labels

				newBodyBytes, err := json.Marshal(payload)
				if err != nil {
					level.Error(options.logger).Log("msg", "failed to marshal modified JSON body, forwarding unmodified", "err", err)
					return
				}

				req.Body = io.NopCloser(bytes.NewBuffer(newBodyBytes))
				req.ContentLength = int64(len(newBodyBytes))
				req.Header.Set("Content-Length", fmt.Sprint(len(newBodyBytes)))
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
