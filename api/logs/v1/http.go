//nolint:funlen
package http

import (
	stdtls "crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/tls"
)

const (
	dialTimeout = 30 * time.Second // Set as in http.DefaultTransport
)

const (
	labelRoute             = "/loki/api/v1/label"
	labelsRoute            = "/loki/api/v1/labels"
	labelValuesRoute       = "/loki/api/v1/label/{name}/values"
	queryRoute             = "/loki/api/v1/query"
	queryRangeRoute        = "/loki/api/v1/query_range"
	seriesRoute            = "/loki/api/v1/series"
	tailRoute              = "/loki/api/v1/tail"
	rulesRoute             = "/loki/api/v1/rules"
	rulesPerNamespaceRoute = "/loki/api/v1/rules/{namespace}"
	rulesPerGroupNameRoute = "/loki/api/v1/rules/{namespace}/{groupName}"

	prometheusRulesRoute  = "/prometheus/api/v1/rules"
	prometheusAlertsRoute = "/prometheus/api/v1/alerts"

	// Legacy APIs for Grafana <= 6.

	promQueryRoute             = "/api/prom/query"
	promLabelRoute             = "/api/prom/label"
	promLabelValuesRoute       = "/api/prom/label/{name}/values"
	promSeriesRoute            = "/api/prom/series"
	promTailRoute              = "/api/prom/tail"
	promRulesRoute             = "/api/prom/rules"
	promRulesPerNamespaceRoute = "/api/prom/rules/{namespace}"
	promRulesPerGroupNameRoute = "/api/prom/rules/{namespace}/{groupName}"
)

type handlerConfiguration struct {
	logger                log.Logger
	registry              *prometheus.Registry
	instrument            handlerInstrumenter
	spanRoutePrefix       string
	rulesLabelFilters     map[string][]string
	readMiddlewares       []func(http.Handler) http.Handler
	writeMiddlewares      []func(http.Handler) http.Handler
	rulesReadMiddlewares  []func(http.Handler) http.Handler
	rulesWriteMiddlewares []func(http.Handler) http.Handler
}

// HandlerOption modifies the handler's configuration.
type HandlerOption func(h *handlerConfiguration)

// Logger add a custom logger for the handler to use.
func Logger(logger log.Logger) HandlerOption {
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

// WithRulesLabelFilters adds the slice of rule labels filters to the handler configuration.
func WithRulesLabelFilters(f map[string][]string) HandlerOption {
	return func(h *handlerConfiguration) {
		h.rulesLabelFilters = f
	}
}

// WithReadMiddleware adds a middleware for all read operations.
func WithReadMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.readMiddlewares = append(h.readMiddlewares, m)
	}
}

// WithWriteMiddleware adds a middleware for all write operations.
func WithWriteMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.writeMiddlewares = append(h.writeMiddlewares, m)
	}
}

// WithRulesWriteMiddleware adds a middleware for all rules write operations.
func WithRulesReadMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.rulesReadMiddlewares = append(h.rulesReadMiddlewares, m)
	}
}

// WithRulesWriteMiddleware adds a middleware for all rules write operations.
func WithRulesWriteMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.rulesWriteMiddlewares = append(h.rulesWriteMiddlewares, m)
	}
}

// WithGlobalMiddleware adds a middleware for all operations.
func WithGlobalMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.writeMiddlewares = append(h.writeMiddlewares, m...)
		h.readMiddlewares = append(h.readMiddlewares, m...)
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

func NewHandler(read, tail, write, rules *url.URL, rulesReadOnly bool, upstreamCA []byte, upstreamCert *stdtls.Certificate, opts ...HandlerOption) http.Handler {
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
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-read"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: dialTimeout,
				}).DialContext,
				TLSClientConfig: tls.NewClientConfig(upstreamCA, upstreamCert),
			}

			proxyRead = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			r.Handle(queryRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, proxyRead),
			))
			r.Handle(queryRangeRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query_range"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+queryRangeRoute, proxyRead),
			))
			r.Handle(labelRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelRoute, proxyRead),
			))
			r.Handle(labelsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "labels"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelsRoute, proxyRead),
			))
			r.Handle(labelValuesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label_values"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+labelValuesRoute, proxyRead),
			))
			r.Handle(seriesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "series"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+seriesRoute, proxyRead),
			))
			r.Handle(promQueryRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "query"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promQueryRoute, proxyRead),
			))
			r.Handle(promLabelRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promLabelRoute, proxyRead),
			))
			r.Handle(promLabelValuesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "label_values"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promLabelValuesRoute, proxyRead),
			))
			r.Handle(promSeriesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "series"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promSeriesRoute, proxyRead),
			))
		})
	}

	if rules != nil {
		var proxyReadRules, proxyWriteRules http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(rules),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-rules"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: dialTimeout,
				}).DialContext,
				TLSClientConfig: tls.NewClientConfig(upstreamCA, upstreamCert),
			}

			proxyReadRules = &httputil.ReverseProxy{
				Director:       middlewares,
				ErrorLog:       proxy.Logger(c.logger),
				Transport:      otelhttp.NewTransport(t),
				ModifyResponse: newModifyResponse(c.logger, c.rulesLabelFilters),
			}

			proxyWriteRules = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			r.Use(c.rulesReadMiddlewares...)
			r.Get(rulesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+rulesRoute, proxyReadRules),
			))
			r.Get(rulesPerNamespaceRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerNamespaceRoute, proxyReadRules),
			))
			r.Get(rulesPerGroupNameRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerGroupNameRoute, proxyReadRules),
			))
			r.Get(prometheusRulesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+prometheusRulesRoute, proxyReadRules),
			))
			r.Get(prometheusAlertsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "alerts"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+prometheusAlertsRoute, proxyReadRules),
			))
			r.Get(promRulesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesRoute, proxyReadRules),
			))
			r.Get(promRulesPerNamespaceRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerNamespaceRoute, proxyReadRules),
			))
			r.Get(promRulesPerGroupNameRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerGroupNameRoute, proxyReadRules),
			))
		})

		if !rulesReadOnly {
			r.Group(func(r chi.Router) {
				r.Use(c.writeMiddlewares...)
				r.Use(c.rulesWriteMiddlewares...)
				r.Post(rulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerNamespaceRoute, proxyWriteRules),
				))
				r.Delete(rulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerNamespaceRoute, proxyWriteRules),
				))
				r.Delete(rulesPerGroupNameRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerGroupNameRoute, proxyWriteRules),
				))

				r.Post(promRulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerNamespaceRoute, proxyWriteRules),
				))
				r.Delete(promRulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerNamespaceRoute, proxyWriteRules),
				))
				r.Delete(promRulesPerGroupNameRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerGroupNameRoute, proxyWriteRules),
				))
			})
		}
	}

	if tail != nil {
		var tailRead http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(tail),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-tail"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: dialTimeout,
				}).DialContext,
				TLSClientConfig: tls.NewClientConfig(upstreamCA, upstreamCert),
			}

			tailRead = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: t,
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			r.Handle(tailRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "tail"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+tailRoute, tailRead),
			))
			r.Handle(promTailRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "prom_tail"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promTailRoute, tailRead),
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
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-write"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: dialTimeout,
				}).DialContext,
				TLSClientConfig: tls.NewClientConfig(upstreamCA, upstreamCert),
			}

			proxyWrite = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			const pushRoute = "/loki/api/v1/push"
			r.Handle(pushRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "push"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+pushRoute, proxyWrite),
			))
		})
	}

	return r
}
