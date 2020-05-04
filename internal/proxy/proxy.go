package proxy

import (
	"bytes"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oxtoacart/bpool"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultBufferCount is the default value for the maximum size of the buffer pool for the reverse proxy.
	DefaultBufferCount = 2 * 1024
	// DefaultBufferSizeBytes is the default value for the length of the buffers in the buffer pool for the reverse proxy.
	DefaultBufferSizeBytes = 32 * 1024
	// DefaultFlushInterval is the default value for the flush interval of reverse proxy to flush to the client while copying the response body.
	DefaultFlushInterval = time.Duration(-1)

	// defaultTimeout is the default value for the maximum amount of time a dial will wait for a connect to complete.
	defaultTimeout = 30 * time.Second
	// defaultKeepAlive is the default value for the interval between keep-alive probes for an active network connection.
	defaultKeepAlive = 30 * time.Second
	// defaultMaxIdleConns is the default value for the maximum idle (keep-alive) connections to keep per-host.
	defaultMaxIdleConns = 100
	// defaultIdleConnTimeout is the default value for the maximum amount of time an idle (keep-alive) connection will remain idle before closing itself.
	defaultIdleConnTimeout = 90 * time.Second
	// defaultTLSHandshakeTimeout is the default value for the maximum amount of time waiting to wait for a TLS handshake.
	defaultTLSHandshakeTimeout = 10 * time.Second
	// defaultExpectContinueTimeout is the default value for the amount of time to wait for a server's first response headers after fully writing the request headers,
	// if the request has an "Expect: 100-continue" header.
	defaultExpectContinueTimeout = 1 * time.Second
)

type Proxy struct {
	logger       log.Logger
	reverseProxy *httputil.ReverseProxy
}

func NewBig(logger log.Logger, prefix string, endpoint *url.URL, opts ...Option) *Proxy {
	options := options{
		bufferCount:           DefaultBufferCount,
		bufferSizeBytes:       DefaultBufferSizeBytes,
		flushInterval:         DefaultFlushInterval,
		maxIdleConns:          defaultMaxIdleConns,
		timeout:               defaultTimeout,
		keepAlive:             defaultKeepAlive,
		idleConnTimeout:       defaultIdleConnTimeout,
		tlsHandshakeTimeout:   defaultTLSHandshakeTimeout,
		expectContinueTimeout: defaultExpectContinueTimeout,
	}

	for _, o := range opts {
		o.apply(&options)
	}

	logger = log.With(logger, "component", "proxy")
	bufferPool := bpool.NewBytePool(options.bufferCount, options.bufferSizeBytes)
	director := func(r *http.Request) {
		if r.Body != nil {
			bodyBytes, _ := ioutil.ReadAll(r.Body)
			r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		level.Debug(logger).Log("endpoint scheme", endpoint.Scheme, "endpoint host", endpoint.Host, "prefix", prefix, "path", r.URL.Path)

		r.URL.Scheme = endpoint.Scheme
		r.URL.Host = endpoint.Host
		r.URL.Path = path.Join(endpoint.Path, strings.TrimPrefix(r.URL.Path, prefix))

		level.Debug(logger).Log("scheme", r.URL.Scheme, "host", r.URL.Host, "path", r.URL.Path)
	}
	stdErrLogger := stdlog.New(log.NewStdlibAdapter(level.Error(logger)), "", stdlog.Lshortfile)

	rev := httputil.ReverseProxy{
		BufferPool:    bufferPool,
		Director:      director,
		ErrorLog:      stdErrLogger,
		FlushInterval: options.flushInterval,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   options.timeout,
				KeepAlive: options.keepAlive,
				DualStack: true,
			}).Dial,
			MaxIdleConns:          options.maxIdleConns,
			IdleConnTimeout:       options.idleConnTimeout,
			TLSHandshakeTimeout:   options.tlsHandshakeTimeout,
			ExpectContinueTimeout: options.expectContinueTimeout,
		},
	}

	return &Proxy{logger: logger, reverseProxy: &rev}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		panic("the http.ResponseWriter passed must be an http.Flusher")
	}

	p.reverseProxy.ServeHTTP(w, r)
}

type Middleware func(r *http.Request)

func Middlewares(middlewares ...Middleware) func(r *http.Request) {
	return func(r *http.Request) {
		for _, m := range middlewares {
			m(r)
		}
	}
}

func MiddlewareSetUpstream(upstream *url.URL) Middleware {
	return func(r *http.Request) {

		r.URL.Scheme = upstream.Scheme
		r.URL.Host = upstream.Host
	}
}

func MiddlewareLogger(logger log.Logger) Middleware {
	return func(r *http.Request) {
		rlogger := log.With(logger, "request", middleware.GetReqID(r.Context()))
		level.Debug(rlogger).Log("msg", "request to upstream", "url", r.URL.String())
	}
}

func MiddlewareMetrics(registry *prometheus.Registry, constLabels prometheus.Labels) Middleware {
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "http_proxy_requests_total",
		Help:        "Counter of proxy HTTP requests.",
		ConstLabels: constLabels,
	}, []string{"method"})

	registry.MustRegister(requests)

	return func(r *http.Request) {
		requests.With(prometheus.Labels{"method": r.Method}).Inc()
	}
}

func Logger(logger log.Logger) *stdlog.Logger {
	return stdlog.New(log.NewStdlibAdapter(level.Warn(logger)), "", stdlog.Lshortfile)
}
