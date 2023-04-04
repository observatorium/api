package v1

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	stdtls "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/proxy"
	"github.com/observatorium/api/tls"
)

const (
	dialTimeout = 30 * time.Second // Set as in http.DefaultTransport
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

// WithRegistry adds a custom Jaeger query for the handler to use.
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

// NewV2Handler creates a trace handler for Jaeger V2 API, web UI, and web UI static content
// The web UI handler is able to rewrite
// HTML to change the <base> attribute so that it works with the Observatorium-style
// "/api/v1/traces/{tenant}/" URLs.
func NewV2Handler(read *url.URL, readTemplate string, upstreamCA []byte, upstreamCert *stdtls.Certificate, opts ...HandlerOption) http.Handler {
	if read == nil && readTemplate == "" {
		panic("missing Jaeger read url")
	}

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
		level.Debug(c.logger).Log("msg", "Configuring upstream Jaeger", "queryv2", read)

		var upstreamMiddleware proxy.Middleware
		if read != nil {
			upstreamMiddleware = proxy.MiddlewareSetUpstream(read)
		} else {
			upstreamMiddleware = middlewareSetTemplatedUpstream(c.logger, readTemplate)
		}

		middlewares := proxy.Middlewares(
			upstreamMiddleware,
			proxy.MiddlewareSetPrefixHeader(),
			proxy.MiddlewareLogger(c.logger),
			proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-read"}),
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

			// This is a key piece, it changes <base href=> tags on text/html content
			ModifyResponse: jaegerUIResponseModifier,
		}
	}

	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		r.Get("/api/traces*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1api", "handler": "traces"},
			proxyRead))
		r.Get("/api/services*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1api", "handler": "services"},
			proxyRead))
		r.Get("/api/dependencies*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1api", "handler": "dependencies"},
			proxyRead))
		r.Get("/static/*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1static", "handler": "ui"},
			proxyRead))
		r.Get("/search*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1ui", "handler": "ui"},
			proxyRead))
		r.Get("/favicon.ico", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1ui", "handler": "ui"},
			proxyRead))
	})

	return r
}

// Parse a URL; if the URL includes `{tenant}` that portion will be replaced by the tenant.
func ExpandTemplatedUpstream(templateUpstream, tenant string) (*url.URL, error) {
	rawTracesReadEndpoint := strings.Replace(templateUpstream, "{tenant}", tenant, 1)
	return url.ParseRequestURI(rawTracesReadEndpoint)
}

// middlewareSetTemplatedUpstream is a variation of proxy.MiddlewareSetUpstream()
// with additional processing if the upstream includes "{tenant}".
func middlewareSetTemplatedUpstream(logger log.Logger, readTemplate string) proxy.Middleware {
	// Cache upstream URLs to avoid re-parse on every read.
	templateToURL := map[string]*url.URL{}

	return func(r *http.Request) {
		tenant, ok := authentication.GetTenant(r.Context())
		if !ok {
			// At this point another middleware must have put the tenant into the context.
			level.Debug(logger).Log("msg", "Internal error; expected tenant in request context")
		}

		upstream, ok := templateToURL[tenant]
		if !ok {
			var err error
			upstream, err = ExpandTemplatedUpstream(readTemplate, tenant)
			if err != nil {
				// Log if the tenant label includes characters that can't appear in a hostname (such as punctuation).
				level.Debug(logger).Log("msg", "Internal error; tenant contains characters that cannot appear in hostname")
			}

			templateToURL[tenant] = upstream
		}

		r.URL.Scheme = upstream.Scheme
		r.URL.Host = upstream.Host
		r.URL.Path = path.Join(upstream.Path, r.URL.Path)
	}
}

func jaegerUIResponseModifier(response *http.Response) error {
	// Only modify successful HTTP with HTML content
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

		b, err := io.ReadAll(reader)
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
		response.Body = io.NopCloser(buf)
	}

	return nil
}
