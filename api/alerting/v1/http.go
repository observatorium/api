package v1

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/server"
	"github.com/observatorium/api/tls"
	"github.com/observatorium/api/tracing"
)

const (
	dialTimeout = 30 * time.Second // Set as in http.DefaultTransport
)

const (
	AlertsRoute   = "/api/v2/alerts"
	SilencesRoute = "/api/v2/silences"
	SilenceRoute  = "/api/v2/silence/{silenceID}"
)

type handlerConfiguration struct {
	logger                    log.Logger
	registry                  *prometheus.Registry
	instrument                handlerInstrumenter
	tenantLabel               string
	alertsReadMiddlewares     []func(http.Handler) http.Handler
	silenceReadMiddlewares    []func(http.Handler) http.Handler
	silenceWriteMiddlewares   []func(http.Handler) http.Handler
	silenceIDReadMiddlewares  []func(http.Handler) http.Handler
	silenceIDWriteMiddlewares []func(http.Handler) http.Handler
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

// WithTenantLabel adds tenant label for the handler to use.
func WithTenantLabel(tenantLabel string) HandlerOption {
	return func(h *handlerConfiguration) {
		h.tenantLabel = tenantLabel
	}
}

// WithAlertsReadMiddleware adds a middleware for the read alerts operation.
func WithAlertsReadMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.alertsReadMiddlewares = append(h.alertsReadMiddlewares, m...)
	}
}

// WithSilenceReadMiddleware adds a middleware for the read silences operation.
func WithSilenceReadMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.silenceReadMiddlewares = append(h.silenceReadMiddlewares, m...)
	}
}

// WithSilenceWriteMiddleware adds a middleware for the create silence operation.
func WithSilenceWriteMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.silenceWriteMiddlewares = append(h.silenceWriteMiddlewares, m...)
	}
}

// WithSilenceIDReadMiddleware adds a middleware for the read silence by ID operation.
func WithSilenceIDReadMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.silenceIDReadMiddlewares = append(h.silenceIDReadMiddlewares, m...)
	}
}

// WithSilenceIDWriteMiddleware adds a middleware for the delete silence by ID operation.
func WithSilenceIDWriteMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.silenceIDWriteMiddlewares = append(h.silenceIDWriteMiddlewares, m...)
	}
}

// WithGlobalMiddleware adds a middleware for all operations.
func WithGlobalMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.alertsReadMiddlewares = append(h.alertsReadMiddlewares, m...)
		h.silenceReadMiddlewares = append(h.silenceReadMiddlewares, m...)
		h.silenceWriteMiddlewares = append(h.silenceWriteMiddlewares, m...)
		h.silenceIDReadMiddlewares = append(h.silenceIDReadMiddlewares, m...)
		h.silenceIDWriteMiddlewares = append(h.silenceIDWriteMiddlewares, m...)
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(_ prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

// NewHandler creates the new alerting v1 handler, proxying a subset of the
// Alertmanager v2 API (active alerts and silences).
func NewHandler(endpoint *url.URL, tlsOptions *tls.UpstreamOptions, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()
	r.Use(tracing.WithChiRoutePattern)
	r.Use(func(handler http.Handler) http.Handler {
		return c.instrument.NewHandler(nil, handler)
	})

	if endpoint == nil {
		return r
	}

	alertmanagerTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: dialTimeout,
		}).DialContext,
		TLSClientConfig: tlsOptions.NewClientConfig(),
	}

	var proxyAlertmanager http.Handler
	{
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(endpoint),
			proxy.MiddlewareSetPrefixHeader(),
			proxy.MiddlewareLogger(c.logger),
			proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "alertingv1-alertmanager"}),
		)

		proxyAlertmanager = &httputil.ReverseProxy{
			Director:  middlewares,
			ErrorLog:  proxy.Logger(c.logger),
			Transport: otelhttp.NewTransport(alertmanagerTransport),
		}
	}

	r.Group(func(r chi.Router) {
		r.Use(func(handler http.Handler) http.Handler {
			return server.InjectLabelsCtx(
				prometheus.Labels{"group": "alertingv1", "handler": "alerts"},
				handler,
			)
		})
		r.Use(c.alertsReadMiddlewares...)
		r.Use(server.StripTenantPrefix("/api/alerting/v1"))

		r.Method(http.MethodGet, AlertsRoute, proxyAlertmanager)
	})

	r.Group(func(r chi.Router) {
		r.Use(func(handler http.Handler) http.Handler {
			return server.InjectLabelsCtx(
				prometheus.Labels{"group": "alertingv1", "handler": "silences"},
				handler,
			)
		})
		r.Use(c.silenceReadMiddlewares...)
		r.Use(server.StripTenantPrefix("/api/alerting/v1"))

		r.Method(http.MethodGet, SilencesRoute, proxyAlertmanager)
	})

	r.Group(func(r chi.Router) {
		r.Use(func(handler http.Handler) http.Handler {
			return server.InjectLabelsCtx(
				prometheus.Labels{"group": "alertingv1", "handler": "silences"},
				handler,
			)
		})
		r.Use(c.silenceWriteMiddlewares...)
		r.Use(WithEnforceTenancyOnSilenceMatchers(c.tenantLabel))
		r.Use(server.StripTenantPrefix("/api/alerting/v1"))

		r.Method(http.MethodPost, SilencesRoute, proxyAlertmanager)
	})

	alertmanagerSilenceTransport := otelhttp.NewTransport(alertmanagerTransport)
	enforceTenancyOnSilenceID := WithEnforceTenancyOnSilenceID(
		c.tenantLabel,
		endpoint,
		alertmanagerSilenceTransport,
	)

	r.Group(func(r chi.Router) {
		r.Use(func(handler http.Handler) http.Handler {
			return server.InjectLabelsCtx(
				prometheus.Labels{"group": "alertingv1", "handler": "silence"},
				handler,
			)
		})
		r.Use(enforceTenancyOnSilenceID)
		r.Use(c.silenceIDReadMiddlewares...)
		r.Use(server.StripTenantPrefix("/api/alerting/v1"))

		r.Method(http.MethodGet, SilenceRoute, proxyAlertmanager)
	})

	r.Group(func(r chi.Router) {
		r.Use(func(handler http.Handler) http.Handler {
			return server.InjectLabelsCtx(
				prometheus.Labels{"group": "alertingv1", "handler": "silence"},
				handler,
			)
		})
		r.Use(enforceTenancyOnSilenceID)
		r.Use(c.silenceIDWriteMiddlewares...)
		r.Use(server.StripTenantPrefix("/api/alerting/v1"))

		r.Method(http.MethodDelete, SilenceRoute, proxyAlertmanager)
	})

	return r
}
