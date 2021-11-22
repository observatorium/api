package v1

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/rules"
)

const (
	readTimeout  = 15 * time.Minute
	writeTimeout = time.Minute
)

const (
	uiRoute          = "/"
	queryRoute       = "/api/v1/query"
	queryRangeRoute  = "/api/v1/query_range"
	seriesRoute      = "/api/v1/series"
	labelNamesRoute  = "/api/v1/labels"
	labelValuesRoute = "/api/v1/label/{label_name}/values"
	receiveRoute     = "/api/v1/receive"
	rulesRoute       = "/api/v1/rules/raw"
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
	spanRoutePrefix  string
	tenantLabel      string
	queryMiddlewares []func(http.Handler) http.Handler
	readMiddlewares  []func(http.Handler) http.Handler
	uiMiddlewares    []func(http.Handler) http.Handler
	writeMiddlewares []func(http.Handler) http.Handler
}

// HandlerOption modifies the handler's configuration.
type HandlerOption func(h *handlerConfiguration)

// WithLogger add a custom logger for the handler to use.
func WithLogger(logger log.Logger) HandlerOption {
	return func(h *handlerConfiguration) {
		h.logger = logger
	}
}

// WithRegistry adds a custom Prometheus registry for the handler to use.
func WithRegistry(r *prometheus.Registry) HandlerOption {
	return func(h *handlerConfiguration) {
		h.registry = r
	}
}

// WithHandlerInstrumenter adds a custom HTTP handler instrument middleware for the handler to use.
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

// WithTenantLabel adds tenant label for the handler to use.
func WithTenantLabel(tenantLabel string) HandlerOption {
	return func(h *handlerConfiguration) {
		h.tenantLabel = tenantLabel
	}
}

// WithReadMiddleware adds a middleware for all "matcher based" read operations (series, label names and values).
func WithReadMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.readMiddlewares = append(h.readMiddlewares, m)
	}
}

// WithQueryMiddleware adds a middleware for all query operations.
func WithQueryMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.queryMiddlewares = append(h.queryMiddlewares, m)
	}
}

// WithUIMiddleware adds a middleware for all non read, non query, non write operations (e.g ui).
func WithUIMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.uiMiddlewares = append(h.uiMiddlewares, m)
	}
}

// WithWriteMiddleware adds a middleware for all write operations.
func WithWriteMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.writeMiddlewares = append(h.writeMiddlewares, m)
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(_ prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

// NewHandler creates the new metrics v1 handler.
// nolint:funlen
func NewHandler(read, write, rulesEndpoint *url.URL, upstreamCA []byte, opts ...HandlerOption) http.Handler {
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
		var proxyQuery http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-query"}),
			)

			proxyQuery = &httputil.ReverseProxy{
				Director: middlewares,
				ErrorLog: proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(
					&http.Transport{
						DialContext: (&net.Dialer{
							Timeout: readTimeout,
						}).DialContext,
					},
				),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.queryMiddlewares...)
			r.Handle(queryRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "query"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, proxyQuery),
			))
			r.Handle(queryRangeRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "query_range"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRangeRoute, proxyQuery),
			))
		})

		var proxyRead http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-read"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: readTimeout,
				}).DialContext,
			}

			if len(upstreamCA) != 0 {
				t.TLSClientConfig = &tls.Config{
					RootCAs: x509.NewCertPool(),
				}
				t.TLSClientConfig.RootCAs.AppendCertsFromPEM(upstreamCA)
			}

			proxyRead = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			r.Handle(seriesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "series"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+seriesRoute, proxyRead),
			))
			r.Handle(labelNamesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "label_names"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelNamesRoute, proxyRead),
			))
			r.Handle(labelValuesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "label_values"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelValuesRoute, proxyRead),
			))
		})

		var uiProxy http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(read),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-ui"}),
			)

			t := http.DefaultTransport.(*http.Transport)
			if len(upstreamCA) != 0 {
				t.TLSClientConfig = &tls.Config{
					RootCAs: x509.NewCertPool(),
				}
				t.TLSClientConfig.RootCAs.AppendCertsFromPEM(upstreamCA)
			}

			uiProxy = &httputil.ReverseProxy{
				Director:  middlewares,
				Transport: otelhttp.NewTransport(http.DefaultTransport),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.uiMiddlewares...)
			r.Mount(uiRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "ui"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+uiRoute, uiProxy),
			))
		})
	}

	if write != nil {
		var proxyWrite http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(write),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-write"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: writeTimeout,
				}).DialContext,
			}

			if len(upstreamCA) != 0 {
				t.TLSClientConfig = &tls.Config{
					RootCAs: x509.NewCertPool(),
				}
				t.TLSClientConfig.RootCAs.AppendCertsFromPEM(upstreamCA)
			}

			proxyWrite = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			r.Handle(receiveRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "metricsv1", "handler": "receive"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+receiveRoute, proxyWrite),
			))
		})
	}

	if rulesEndpoint != nil {
		client, err := rules.NewClient(rulesEndpoint.String())
		if err != nil {
			level.Warn(c.logger).Log("msg", "could not create rules endpoint client")
			return r
		}

		rh := rulesHandler{client: client, logger: c.logger, tenantLabel: c.tenantLabel}

		r.Group(func(r chi.Router) {
			r.Use(c.uiMiddlewares...)
			r.Get(rulesRoute, rh.get)
		})

		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			r.Put(rulesRoute, rh.put)
		})
	}

	return r
}
