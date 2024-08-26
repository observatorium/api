package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/oklog/ulid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/thanos-io/objstore"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/httperr"
	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/rules"
	"github.com/observatorium/api/server"
	"github.com/observatorium/api/tls"
)

const (
	dialTimeout = 30 * time.Second // Set as in http.DefaultTransport
)

const (
	UIRoute          = "/"
	QueryRoute       = "/api/v1/query"
	QueryRangeRoute  = "/api/v1/query_range"
	SeriesRoute      = "/api/v1/series"
	LabelNamesRoute  = "/api/v1/labels"
	LabelValuesRoute = "/api/v1/label/{label_name}/values"
	ReceiveRoute     = "/api/v1/receive"
	RulesRoute       = "/api/v1/rules"
	RulesRawRoute    = "/api/v1/rules/raw"

	UploadRoute = "/api/v1/upload"

	AlertmanagerAlertsRoute   = "/am/api/v2/alerts"
	AlertmanagerSilencesRoute = "/am/api/v2/silences"
)

type alertmanagerMiddleware struct {
	alertsReadMiddlewares   []func(http.Handler) http.Handler
	silenceReadMiddlewares  []func(http.Handler) http.Handler
	silenceWriteMiddlewares []func(http.Handler) http.Handler
}

type handlerConfiguration struct {
	logger                 log.Logger
	registry               *prometheus.Registry
	instrument             handlerInstrumenter
	spanRoutePrefix        string
	tenantLabel            string
	queryMiddlewares       []func(http.Handler) http.Handler
	readMiddlewares        []func(http.Handler) http.Handler
	uiMiddlewares          []func(http.Handler) http.Handler
	writeMiddlewares       []func(http.Handler) http.Handler
	alertmanagerMiddleware alertmanagerMiddleware
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

func WithAlertmanagerAlertsReadMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.alertmanagerMiddleware.alertsReadMiddlewares = append(h.alertmanagerMiddleware.alertsReadMiddlewares, m...)
	}
}

func WithAlertmanagerSilenceReadMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.alertmanagerMiddleware.silenceReadMiddlewares = append(h.alertmanagerMiddleware.silenceReadMiddlewares, m...)
	}
}

func WithAlertmanagerSilenceWriteMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.alertmanagerMiddleware.silenceWriteMiddlewares = append(h.alertmanagerMiddleware.silenceWriteMiddlewares, m...)
	}
}

// WithGlobalMiddleware adds a middleware for all operations.
func WithGlobalMiddleware(m ...func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.writeMiddlewares = append(h.writeMiddlewares, m...)
		h.uiMiddlewares = append(h.uiMiddlewares, m...)
		h.queryMiddlewares = append(h.queryMiddlewares, m...)
		h.readMiddlewares = append(h.readMiddlewares, m...)
		h.alertmanagerMiddleware.alertsReadMiddlewares = append(h.alertmanagerMiddleware.alertsReadMiddlewares, m...)
		h.alertmanagerMiddleware.silenceReadMiddlewares = append(h.alertmanagerMiddleware.silenceReadMiddlewares, m...)
		h.alertmanagerMiddleware.silenceWriteMiddlewares = append(h.alertmanagerMiddleware.silenceWriteMiddlewares, m...)
	}
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(_ prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

type Endpoints struct {
	ReadEndpoint         *url.URL
	WriteEndpoint        *url.URL
	RulesEndpoint        *url.URL
	AlertmanagerEndpoint *url.URL
}

// NewHandler creates the new metrics v1 handler.
// nolint:funlen
func NewHandler(endpoints Endpoints, tlsOptions *tls.UpstreamOptions, bkt objstore.Bucket, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()
	r.Use(func(handler http.Handler) http.Handler {
		return c.instrument.NewHandler(nil, handler)
	})

	if endpoints.ReadEndpoint != nil {
		var proxyQuery http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(endpoints.ReadEndpoint),
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
							Timeout: dialTimeout,
						}).DialContext,
					},
				),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "query"},
					handler,
				)
			})
			r.Use(c.queryMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Handle(QueryRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+QueryRoute,
					proxyQuery,
				),
			)
		})
		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "query_range"},
					handler,
				)
			})
			r.Use(c.queryMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Handle(QueryRangeRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+QueryRangeRoute,
					proxyQuery,
				),
			)
		})

		var proxyRead http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(endpoints.ReadEndpoint),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-read"}),
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
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "series"},
					handler,
				)
			})
			r.Use(c.readMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Handle(SeriesRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+SeriesRoute,
					proxyRead,
				),
			)
		})
		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "label_names"},
					handler,
				)
			})
			r.Use(c.readMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Handle(LabelNamesRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+LabelNamesRoute,
					proxyRead,
				),
			)
		})
		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "label_values"},
					handler,
				)
			})
			r.Use(c.readMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Handle(LabelValuesRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+LabelValuesRoute,
					proxyRead,
				),
			)
		})

		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "rules"},
					handler,
				)
			})
			r.Use(c.readMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			// Thanos Query Rules API supports matchers from v0.25 so the WithEnforceTenancyOnMatchers
			// middleware will not work here if prior versions are used.
			r.Handle(RulesRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+RulesRoute,
					proxyRead,
				),
			)
		})

		var uiProxy http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(endpoints.ReadEndpoint),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-ui"}),
			)

			t := http.DefaultTransport.(*http.Transport)
			t.TLSClientConfig = tlsOptions.NewClientConfig()

			uiProxy = &httputil.ReverseProxy{
				Director:  middlewares,
				Transport: otelhttp.NewTransport(http.DefaultTransport),
			}
		}
		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "ui"},
					handler,
				)
			})
			r.Use(c.uiMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Mount(UIRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+UIRoute,
					uiProxy,
				),
			)
		})
	}

	if endpoints.WriteEndpoint != nil {
		var proxyWrite http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(endpoints.WriteEndpoint),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "metricsv1-write"}),
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
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "receive"},
					handler,
				)
			})
			r.Use(c.writeMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Handle(ReceiveRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+ReceiveRoute,
					proxyWrite,
				),
			)
		})
	}

	if endpoints.RulesEndpoint != nil {
		client, err := rules.NewClient(endpoints.RulesEndpoint.String())
		if err != nil {
			level.Warn(c.logger).Log("msg", "could not create rules endpoint client")
			return r
		}

		rh := rulesHandler{client: client, logger: c.logger, tenantLabel: c.tenantLabel}

		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "rules"},
					handler,
				)
			})
			r.Use(c.uiMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Method(http.MethodGet, RulesRawRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+RulesRawRoute,
					http.HandlerFunc(rh.get),
				),
			)
		})

		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "rules-raw"},
					handler,
				)
			})
			r.Use(c.writeMiddlewares...)
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Method(http.MethodPut, RulesRawRoute,
				otelhttp.WithRouteTag(
					c.spanRoutePrefix+RulesRawRoute,
					http.HandlerFunc(rh.put),
				),
			)
		})
	}

	if endpoints.AlertmanagerEndpoint != nil {
		var proxyAlertmanager http.Handler
		{
			middlewares := proxy.Middlewares(
				proxy.MiddlewareSetUpstream(endpoints.AlertmanagerEndpoint),
				proxy.MiddlewareSetPrefixHeader(),
				proxy.MiddlewareLogger(c.logger),
				proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "alertmanagerv2"}),
			)

			t := &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: dialTimeout,
				}).DialContext,
				TLSClientConfig: tlsOptions.NewClientConfig(),
			}

			proxyAlertmanager = &httputil.ReverseProxy{
				Director:  middlewares,
				ErrorLog:  proxy.Logger(c.logger),
				Transport: otelhttp.NewTransport(t),
			}
		}

		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "alerts"},
					handler,
				)
			})
			r.Use(c.alertmanagerMiddleware.alertsReadMiddlewares...)
			r.Use(server.StripTenantPrefixWithSubRoute("/api/metrics/v1", "/am"))

			r.Method(http.MethodGet, AlertmanagerAlertsRoute, otelhttp.WithRouteTag(
				c.spanRoutePrefix+AlertmanagerAlertsRoute,
				proxyAlertmanager,
			))
		})

		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "silences"},
					handler,
				)
			})
			r.Use(c.alertmanagerMiddleware.silenceReadMiddlewares...)
			r.Use(server.StripTenantPrefixWithSubRoute("/api/metrics/v1", "/am"))

			r.Method(http.MethodGet, AlertmanagerSilencesRoute, otelhttp.WithRouteTag(
				c.spanRoutePrefix+AlertmanagerSilencesRoute,
				proxyAlertmanager,
			))
		})

		r.Group(func(r chi.Router) {
			r.Use(func(handler http.Handler) http.Handler {
				return server.InjectLabelsCtx(
					prometheus.Labels{"group": "metricsv1", "handler": "silences"},
					handler,
				)
			})
			r.Use(c.alertmanagerMiddleware.silenceWriteMiddlewares...)
			r.Use(server.StripTenantPrefixWithSubRoute("/api/metrics/v1", "/am"))

			r.Method(http.MethodPost, AlertmanagerSilencesRoute, otelhttp.WithRouteTag(
				c.spanRoutePrefix+AlertmanagerSilencesRoute,
				proxyAlertmanager,
			))
		})
	}
	if bkt != nil {
		r.Group(func(r chi.Router) {
			r.Use(server.StripTenantPrefix("/api/metrics/v1"))
			r.Post(UploadRoute, func(w http.ResponseWriter, r *http.Request) {
				// Reduce memory usage of multipart data. This indicates memory will be used
				// before writting to disk. Default: 8MB
				err := r.ParseMultipartForm(8)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("Unable to parse form data"))
					return
				}

				file, fileHeader, fileErr := r.FormFile("file")
				if fileErr != nil {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("File field not found"))
					return
				}
				defer file.Close()

				// Below check make sure file size does not exceeds 200MB
				if fileHeader.Size > 200_000_000 {
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					w.Write([]byte(fmt.Sprintf("File exceeds maximum file size 200MB for upload: %v", fileHeader.Size)))
				}

				var relabelConfig []*relabel.Config
				tenantID, ok := authentication.GetTenantID(r.Context())
				if !ok {
					httperr.PrometheusAPIError(w, "error finding tenant ID", http.StatusInternalServerError)
					return
				}
				relabelConfig = append(relabelConfig, NewRelabelConfig(c.tenantLabel, tenantID))

				// Adding external_labels to tsdb
				var external_labels map[string]string
				l := r.FormValue("external_labels")
				if l != "" {
					if err = json.Unmarshal([]byte(l), &external_labels); err != nil {
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte("unable to unmarshal external labels"))
					}
				}
				for eLabelName, eLabelValue := range external_labels {
					relabelConfig = append(relabelConfig, NewRelabelConfig(eLabelName, eLabelValue))
				}

				tsdbDir, err := os.MkdirTemp("/tmp", "tsdb")
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("unable to create directory to extract archive"))
					return
				}
				defer os.RemoveAll(tsdbDir)

				err = ExtractTarGz(file, tsdbDir)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("unable to extract archive"))
					return
				}

				{
					files, err := os.ReadDir(tsdbDir)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("unable to read extracted archive data"))
						return
					}

					newTSDBDir, err := os.MkdirTemp("/tmp", "new-tsdb")
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("unable to create temporary directory for newtsdb blocks"))
						return
					}
					defer os.RemoveAll(newTSDBDir)

					for _, file := range files {

						if _, err := ulid.Parse(file.Name()); err != nil {
							continue
						}

						if err := ReLabelTSDB(c.logger, file.Name(), tsdbDir+"/"+file.Name(), newTSDBDir, relabelConfig); err != nil {
							level.Error(c.logger).Log(err)
							w.WriteHeader(http.StatusInternalServerError)
							w.Write([]byte(fmt.Sprintf("error writting tsdb blocks - %v", err)))
							return
						}
					}

					if ok, _ := IsDirEmpty(newTSDBDir); ok {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("didn't created any new tsdb blocks"))
					} else {
						if err := objstore.UploadDir(context.Background(), c.logger, bkt, newTSDBDir, ""); err == nil {
							w.Write([]byte("new tsdb created successfully"))
						} else {
							level.Error(c.logger).Log(err)
							w.Write([]byte(fmt.Sprintf("Failed to upload to object storage - %v", err)))
						}
					}
				}
			})
		})
	}

	return r
}
