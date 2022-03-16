package v1

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/proxy"
)

const (
	ReadTimeout  = 15 * time.Minute
	WriteTimeout = time.Minute
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
	spanRoutePrefix  string
	readMiddlewares  []func(http.Handler) http.Handler
	writeMiddlewares []func(http.Handler) http.Handler
}

// HandlerOption modifies the handler's configuration.
type HandlerOption func(h *handlerConfiguration)

// Logger add a custom logger for the handler to use.
func Logger(logger log.Logger) HandlerOption {
	return func(h *handlerConfiguration) {
		h.logger = logger
	}
}

// WithJaegerQueryV3 adds a custom Jaeger query for the handler to use.
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

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

// NewV2APIHandler creates a trace query handler for Jaeger V2 HTTP queries
func NewV2APIHandler(read *url.URL, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()

	var proxyRead http.Handler
	{
		level.Debug(c.logger).Log("msg", "Configuring upstream Jaeger query v2", "queryv2", read)
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(read),
			proxy.MiddlewareSetPrefixHeader(),
			proxy.MiddlewareLogger(c.logger),
			proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-read"}),
		)

		t := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ReadTimeout,
			}).DialContext,
		}

		proxyRead = &httputil.ReverseProxy{
			Director:     middlewares,
			ErrorLog:     proxy.Logger(c.logger),
			Transport:    otelhttp.NewTransport(t),
			ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {},
		}
	}
	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		r.Handle("/*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1api", "handler": "api"},
			proxyRead))
	})

	return r
}

// NewUIStaticHandler creates a trace handler for Jaeger UI static assets (.js and .css)
func NewUIStaticHandler(read *url.URL, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()

	var proxyRead http.Handler
	{
		level.Debug(c.logger).Log("msg", "Configuring upstream Jaeger UI static", "ui", read)
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(read),
			proxy.MiddlewareSetPrefixHeader(),
			proxy.MiddlewareLogger(c.logger),
			proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-ui-static"}),
		)

		t := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ReadTimeout,
			}).DialContext,
		}

		proxyRead = &httputil.ReverseProxy{
			Director:  middlewares,
			ErrorLog:  proxy.Logger(c.logger),
			Transport: otelhttp.NewTransport(t),
		}
	}
	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		r.Handle("/*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1ui", "handler": "search"},
			proxyRead))
	})

	return r
}

// NewUIHandler creates a trace handler for Jaeger UI that is able to re-write
// HTML to change the <base> attribute so that it works with the Observatorium-style
// "/api/v1/traces/{tenant}/" URLs.
func NewUIHandler(read *url.URL, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}

	for _, o := range opts {
		o(c)
	}

	r := chi.NewRouter()

	var proxyRead http.Handler
	{
		level.Debug(c.logger).Log("msg", "Configuring upstream Jaeger UI", "ui", read)
		middlewares := proxy.Middlewares(
			proxy.MiddlewareSetUpstream(read),
			proxy.MiddlewareSetPrefixHeader(),
			proxy.MiddlewareLogger(c.logger),
			proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-ui"}),
		)

		t := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ReadTimeout,
			}).DialContext,
		}

		proxyRead = &httputil.ReverseProxy{
			Director:  middlewares,
			ErrorLog:  proxy.Logger(c.logger),
			Transport: otelhttp.NewTransport(t),

			// This is the key piece, it changes <base href=> tags
			ModifyResponse: jaegerUIResponseModifier,
		}
	}

	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		r.Handle("/*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1ui", "handler": "search"},
			proxyRead))
	})

	return r
}

func jaegerUIResponseModifier(response *http.Response) error {
	// Only modify successful HTTP
	if response.StatusCode == http.StatusOK && strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") {
		// Do man-in-the-middle rewriting of the UI HTML.
		var err error

		// Uncompressed reader
		var reader io.ReadCloser

		// Read what Jaeger UI sent back (which might be compressed)
		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, err = gzip.NewReader(response.Body)
			if err != nil {
				return err
			}
			defer reader.Close()
		case "deflate":
			reader = flate.NewReader(response.Body)
			defer reader.Close()
		default:
			reader = response.Body
		}

		b, err := ioutil.ReadAll(reader)
		if err != nil {
			return err
		}

		// At this point we have read the body.  Even if it didn't have a <body href=>
		// to modify, we need to create a new Reader.  This code thus executes all the time.

		// JaegerUI insists on a <base>, so create one but use Observatorium's
		// opinion of the base href, not Jaeger Query's opinion.
		forwardedPrefix := response.Request.Header.Get(proxy.PrefixHeader)

		// The <base href=> tag generated by Jaeger to tell the UI where to fetch static
		// assets and query /api
		const expectedBaseTag = `<base href="/" data-inject-target="BASE_URL"/>`

		replacementBaseTag := fmt.Sprintf(`<base href="%s/" data-inject-target="BASE_URL"/>`, forwardedPrefix)
		strResponse := strings.Replace(string(b), expectedBaseTag, replacementBaseTag, 1)

		// We could re-encode in gzip/deflate, but there is no need, so send it raw
		response.Header["Content-Encoding"] = []string{}
		buf := bytes.NewBufferString(strResponse)
		response.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}
		response.Body = ioutil.NopCloser(buf)
	}

	return nil
}
