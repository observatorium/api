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
	fmt.Printf("@@@ ecs REACHED NewV2APIHandler()\n")
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
			// @@@ TODO restore? proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-read"}),
		)

		t := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ReadTimeout,
			}).DialContext,
		}

		fmt.Printf("@@@ ecs constructing reverse proxy for traces\n")
		proxyRead = &httputil.ReverseProxy{
			Director:     middlewares,
			ErrorLog:     proxy.Logger(c.logger),
			Transport:    otelhttp.NewTransport(t),
			ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {},
		}
	}
	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		const (
			queryRoute      = "/api/traces"
			servicesRoute   = "/api/services"
			operationsRoute = "/api/operations"
		)
		r.Handle(queryRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1", "handler": "query"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+queryRoute, proxyRead)))
		r.Handle(servicesRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1", "handler": "query_range"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+servicesRoute, proxyRead)))
		r.Handle(operationsRoute, c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1", "handler": "query_range"},
			otelhttp.WithRouteTag(c.spanRoutePrefix+operationsRoute, proxyRead)))
	})

	return r
}

// NewUIHandler creates a trace handler for Jaeger UI
func NewUIHandler(read *url.URL, opts ...HandlerOption) http.Handler {
	fmt.Printf("@@@ ecs REACHED NewUIHandler()\n")
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
			// @@@ TODO restore? proxy.MiddlewareMetrics(c.registry, prometheus.Labels{"proxy": "tracesv1-read"}),
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
			ErrorHandler: func(rw http.ResponseWriter, r *http.Request, e error) {
				fmt.Printf("@@@ ecs in NewUIHandler anon ErrorHandler for request %q: %v\n", r.URL.String(), e)
			},
			ModifyResponse: jaegerUIResponseModifier,
		}
	}
	r.Group(func(r chi.Router) {
		r.Use(c.readMiddlewares...)
		/*
			const (
				searchRoute  = "/search"
				staticRoute  = "/static/*"
				faviconRoute = "/favicon.ico"
			)
			r.Handle(searchRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "tracesv1ui", "handler": "search"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+searchRoute, proxyRead)))
			r.Handle(staticRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "tracesv1ui", "handler": "static"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+staticRoute, proxyRead)))
			r.Handle(faviconRoute, c.instrument.NewHandler(
				prometheus.Labels{"group": "tracesv1ui", "handler": "static"},
				otelhttp.WithRouteTag(c.spanRoutePrefix+faviconRoute, proxyRead)))
		*/
		r.Handle("/*", c.instrument.NewHandler(
			prometheus.Labels{"group": "tracesv1ui", "handler": "search"},
			proxyRead))
	})

	return r
}

func jaegerUIResponseModifier(response *http.Response) error {
	// fmt.Printf("@@@ ecs REACHED jaegerUIResponseModifier(), content type is %q\n", response.Header.Get("Content-Type"))
	// @@@ md, err := metadata.FromIncomingContext(response.Request.Context())
	// fmt.Printf("@@@ ecs REACHED jaegerUIResponseModifier, request tenant was %v\n", response.Request.Context().Value("tenant"))
	// fmt.Printf("@@@ ecs REACHED jaegerUIResponseModifier, request tenantID was %v\n", response.Request.Context().Value("tenantID"))
	// fmt.Printf("@@@ ecs REACHED jaegerUIResponseModifier, request context is %#v, a %T\n", response.Request.Context(), response.Request.Context())
	// fmt.Printf("@@@ ecs REACHED jaegerUIResponseModifier, request header is %#v, a %T\n", response.Request.Header, response.Request.Header)

	// if response.StatusCode == http.StatusOK && response.Header.Get("Content-Type") == "text/html; charset=utf-8" {
	if response.StatusCode == http.StatusOK && response.Header.Get("Content-Type") == "text/html; charset=utf-8" {
		fmt.Printf("@@@ ecs in jaegerUIResponseModifier() for %v\n", response.Request.URL)
		var reader io.ReadCloser
		var err error
		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, err = gzip.NewReader(response.Body)
			if err != nil {
				return err
			}
			defer reader.Close()
		case "deflate":
			fmt.Printf("@@@ ecs jaegerUIResponseModifier got deflated data for %v\n", response.Request.URL.String())
			reader = flate.NewReader(response.Body)
			defer reader.Close()
		default:
			fmt.Printf("@@@ ecs jaegerUIResponseModifier got content encoding %q for %v\n", response.Header.Get("Content-Encoding"), response.Request.URL.String())
			reader = response.Body
		}

		b, err := ioutil.ReadAll(reader)
		if err != nil {
			return err
		}

		fmt.Printf("@@@ ecs jaegerUIResponseModifier() decoded body\n")

		// JaegerUI insists on a <base>, so create one but use Observatorium's
		// opinion of the base href, not Jaeger Query's opinion.
		// TODO Use github.com/observatorium/api/proxy/prefixHeader
		forwardedPrefix := response.Request.Header.Get("X-Forwarded-Prefix")
		if forwardedPrefix == "" {
			// TODO Log the first time this happens?  It should never happen.
			forwardedPrefix = "/api/traces/v1/dummy"
		}

		// fmt.Printf("@@@ ecs in jaegerUIResponseModifier, b is %q\n", b)
		strResponse := string(b)
		const expectedBaseTag = `<base href="/" data-inject-target="BASE_URL"/>`
		replacementBaseTag := fmt.Sprintf(`<base href="%s/" data-inject-target="BASE_URL"/>`, forwardedPrefix)
		if strings.Contains(strResponse, expectedBaseTag) {
			fmt.Printf("@@@ ecs found <base> tag, removing\n")
			strResponse = strings.Replace(strResponse, expectedBaseTag, replacementBaseTag, 1)

			// En-encode the body to match the promised content-encoding

			switch response.Header.Get("Content-Encoding") {
			case "gzip":
				var buf bytes.Buffer
				writer := gzip.NewWriter(&buf)
				writer.Write([]byte(strResponse))
				writer.Close()
				response.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}
				fmt.Printf("@@@ ecs replying with gzipped data of length %v\n", buf.Len())
				response.Body = ioutil.NopCloser(&buf)
			case "deflate":
				var buf bytes.Buffer
				writer, _ := flate.NewWriter(&buf, 1)
				writer.Write([]byte(strResponse))
				writer.Close()
				response.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}
				fmt.Printf("@@@ ecs replying with deflated data of length %v\n", buf.Len())
				response.Body = ioutil.NopCloser(&buf)
			default:
				buf := bytes.NewBufferString(strResponse)
				response.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}
				fmt.Printf("@@@ ecs replying with uncompressed data of length %v\n", buf.Len())
				response.Body = ioutil.NopCloser(buf)
			}

		} else {
			fmt.Printf("@@@ ecs jaegerUIResponseModifier() did not find <base> tag in %v\n", response.Header)
		}
	} else {
		fmt.Printf("@@@ ecs jaegerUIResponseModifier() ignored %v\n", response.Request.URL)
	}

	return nil
}
