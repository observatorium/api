//nolint:funlen
package http

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
	volumeRoute            = "/loki/api/v1/index/volume"
	volumeRangeRoute       = "/loki/api/v1/index/volume_range"
	patternsRoute          = "/loki/api/v1/patterns"
	detectedLabelsRoute    = "/loki/api/v1/detected_labels"
	detectedFieldRoute     = "/loki/api/v1/detected_field"
	detectedFieldsRoute    = "/loki/api/v1/detected_fields"

	otlpRoute = "/otlp/v1/logs"
	pushRoute = "/loki/api/v1/push"

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

// WithRulesLabelFilters adds the slice of rule labels filters to the handler configuration.
func WithRulesLabelFilters(f map[string][]string) HandlerOption {
	return func(h *handlerConfiguration) {
		h.rulesLabelFilters = f
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

func NewHandler(read, tail, write, rules *url.URL, rulesReadOnly bool, tlsOptions *tls.UpstreamOptions, opts ...HandlerOption) http.Handler {
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
				TLSClientConfig: tlsOptions.NewClientConfig(),
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
			r.Handle(volumeRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "volume"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+volumeRoute, proxyRead),
			))
			r.Handle(volumeRangeRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "volume_range"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+volumeRangeRoute, proxyRead),
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
			r.Handle(patternsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "patterns"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+patternsRoute, proxyRead),
			))
			r.Handle(detectedLabelsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "detected_labels"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promSeriesRoute, proxyRead),
			))
			r.Handle(detectedFieldRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "detected_field`"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promSeriesRoute, proxyRead),
			))
			r.Handle(detectedFieldsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "detected_fields`"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promSeriesRoute, proxyRead),
			))
		})
	}

	if rules != nil {
		var proxyRules, proxyPrometheusReadRules http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(rules),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "logsv1-rules"}),
			)

			logger := proxy.Logger(c.logger)
			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: dialTimeout,
				}).DialContext,
				TLSClientConfig: tlsOptions.NewClientConfig(),
			}
			transport := otelhttp.NewTransport(t)

			proxyPrometheusReadRules = &httputil.ReverseProxy{
				Director:       middlewares,
				ErrorLog:       logger,
				Transport:      transport,
				ModifyResponse: newModifyResponseProm(c.logger, c.rulesLabelFilters),
			}
			proxyRules = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  logger,
				Transport: transport,
			}

		}
		r.Group(func(r chi.Router) {
			r.Use(c.readMiddlewares...)
			r.Use(c.rulesReadMiddlewares...)
			r.Get(rulesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+rulesRoute, proxyRules),
			))
			r.Get(rulesPerNamespaceRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerNamespaceRoute, proxyRules),
			))
			r.Get(rulesPerGroupNameRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerGroupNameRoute, proxyRules),
			))
			r.Get(prometheusRulesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+prometheusRulesRoute, proxyPrometheusReadRules),
			))
			r.Get(prometheusAlertsRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "alerts"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+prometheusAlertsRoute, proxyPrometheusReadRules),
			))
			r.Get(promRulesRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesRoute, proxyRules),
			))
			r.Get(promRulesPerNamespaceRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerNamespaceRoute, proxyRules),
			))
			r.Get(promRulesPerGroupNameRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "rules"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerGroupNameRoute, proxyRules),
			))
		})

		if !rulesReadOnly {
			r.Group(func(r chi.Router) {
				r.Use(c.writeMiddlewares...)
				r.Use(c.rulesWriteMiddlewares...)
				r.Post(rulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerNamespaceRoute, proxyRules),
				))
				r.Delete(rulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerNamespaceRoute, proxyRules),
				))
				r.Delete(rulesPerGroupNameRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+rulesPerGroupNameRoute, proxyRules),
				))

				r.Post(promRulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerNamespaceRoute, proxyRules),
				))
				r.Delete(promRulesPerNamespaceRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerNamespaceRoute, proxyRules),
				))
				r.Delete(promRulesPerGroupNameRoute, c.instrument.NewHandler(
					prometheus.Labels{"group": "logsv1", "handler": "rules"},
					otelhttp.WithRouteTag(c.spanRoutePrefix+promRulesPerGroupNameRoute, proxyRules),
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
				TLSClientConfig: tlsOptions.NewClientConfig(),
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
				TLSClientConfig: tlsOptions.NewClientConfig(),
			}

			proxyWrite = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(c.writeMiddlewares...)
			r.Handle(otlpRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "otlp"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+otlpRoute, proxyWrite),
			))
			r.Handle(pushRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "logsv1", "handler": "push"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+pushRoute, proxyWrite),
			))
		})
	}

	return r
}
