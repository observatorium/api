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

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oxtoacart/bpool"
)

const (
	// DefaultBufferCount TODO
	DefaultBufferCount = 2 * 1024
	// DefaultBufferSizeBytes TODO
	DefaultBufferSizeBytes = 32 * 1024
	// DefaultFlushInterval TODO
	DefaultFlushInterval = time.Duration(-1)
	// DefaultTimeout TODO
	DefaultTimeout = 30 * time.Second
	// DefaultKeepAlive TODO
	DefaultKeepAlive = 30 * time.Second
	// DefaultMaxIdleConns TODO
	DefaultMaxIdleConns = 100
	// DefaultIdleConnTimeout TODO
	DefaultIdleConnTimeout = 90 * time.Second
	// DefaultTLSHandshakeTimeout TODO
	DefaultTLSHandshakeTimeout = 10 * time.Second
	// DefaultExpectContinueTimeout TODO
	DefaultExpectContinueTimeout = 1 * time.Second
)

type Proxy struct {
	logger       log.Logger
	reverseProxy *httputil.ReverseProxy
}

func New(logger log.Logger, prefix string, endpoint *url.URL, opts ...Option) *Proxy {
	options := options{
		bufferCount:           DefaultBufferCount,
		bufferSizeBytes:       DefaultBufferSizeBytes,
		maxIdleConns:          DefaultMaxIdleConns,
		flushInterval:         DefaultFlushInterval,
		timeout:               DefaultTimeout,
		keepAlive:             DefaultKeepAlive,
		idleConnTimeout:       DefaultIdleConnTimeout,
		tlsHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		expectContinueTimeout: DefaultExpectContinueTimeout,
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
