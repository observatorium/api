package proxy

import (
	"bytes"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
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
)

type Proxy struct {
	logger       log.Logger
	reverseProxy *httputil.ReverseProxy
}

func New(logger log.Logger, prefix string, endpoint *url.URL, opts ...Option) *Proxy {
	options := options{
		bufferCount:     DefaultBufferCount,
		bufferSizeBytes: DefaultBufferSizeBytes,
		flushInterval:   DefaultFlushInterval,
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

		r.URL.Scheme = endpoint.Scheme
		r.URL.Host = endpoint.Host
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)

		if r.URL.Path == "" {
			r.URL.Path = "/"
		}

		log.With(level.Debug(logger)).Log("scheme", r.URL.Scheme, "host", r.URL.Host, "path", r.URL.Path)
	}
	stdErrlogger := stdlog.New(log.NewStdlibAdapter(level.Error(logger)), "", stdlog.Lshortfile)

	rev := httputil.ReverseProxy{
		BufferPool:    bufferPool,
		Director:      director,
		ErrorLog:      stdErrlogger,
		FlushInterval: options.flushInterval,
	}

	return &Proxy{logger: logger, reverseProxy: &rev}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		panic("the http.ResponseWriter passed must be an http.Flusher")
	}

	p.reverseProxy.ServeHTTP(w, r)
}
