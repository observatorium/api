package proxy

import (
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/oxtoacart/bpool"
)

const (
	DefaultBufferCount     = 2 * 1024
	DefaultBufferSizeBytes = 32 * 1024
)

type Proxy struct {
	logger       log.Logger
	reverseProxy *httputil.ReverseProxy
}

func New(logger log.Logger, prefix string, endpoint *url.URL, opts ...Option) *Proxy {
	options := options{
		bufferCount:     DefaultBufferCount,
		bufferSizeBytes: DefaultBufferSizeBytes,
	}

	for _, o := range opts {
		o.apply(&options)
	}

	bufferPool := bpool.NewBytePool(options.bufferCount, options.bufferSizeBytes)

	director := func(r *http.Request) {
		r.URL.Scheme = endpoint.Scheme
		r.URL.Host = endpoint.Host
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	}

	logger = log.With(level.Error(logger), "component", "proxy")
	stdErrlogger := stdlog.New(log.NewStdlibAdapter(logger), "proxy", stdlog.LstdFlags)

	rev := httputil.ReverseProxy{
		Director:   director,
		BufferPool: bufferPool,
		ErrorLog:   stdErrlogger,
	}

	return &Proxy{logger: logger, reverseProxy: &rev}
}

func (p *Proxy) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	p.reverseProxy.ServeHTTP(resp, req)
}
