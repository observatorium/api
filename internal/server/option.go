package server

import (
	"crypto/tls"
	"net/url"
	"time"

	"github.com/observatorium/observatorium/internal/proxy"
)

type options struct {
	gracePeriod    time.Duration
	timeout        time.Duration
	requestTimeout time.Duration
	readTimeout    time.Duration
	writeTimeout   time.Duration

	tlsConfig *tls.Config

	metricsUIEndpoint    *url.URL
	metricsReadEndpoint  *url.URL
	metricsWriteEndpoint *url.URL

	listen string

	proxyOptions []proxy.Option
}

// Option overrides behavior of Server.
type Option interface {
	apply(*options)
}

type optionFunc func(*options)

func (f optionFunc) apply(o *options) {
	f(o)
}

// WithListen sets the port to listen for the server.
func WithListen(s string) Option {
	return optionFunc(func(o *options) {
		o.listen = s
	})
}

// WithRequestTimeout sets the timeout duration for an individual request.
func WithRequestTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.requestTimeout = t
	})
}

// WithReadTimeout sets the read timeout duration  for the underlying HTTP server.
func WithReadTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.readTimeout = t
	})
}

// WithWriteTimeout sets the write timeout duration  for the underlying HTTP server.
func WithWriteTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.writeTimeout = t
	})
}

// WithTLSConfig TODO
func WithTLSConfig(c *tls.Config) Option {
	return optionFunc(func(o *options) {
		o.tlsConfig = c
	})
}

// WithMetricUIEndpoint TODO
func WithMetricUIEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsUIEndpoint = u
	})
}

// WithMetricReadEndpoint sets the URL to proxy metrics read request to.
func WithMetricReadEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsReadEndpoint = u
	})
}

// WithMetricWriteEndpoint sets the URL to proxy metrics write request to.
func WithMetricWriteEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsWriteEndpoint = u
	})
}

// WithProxyOptions sets the proxy options fot the underlying reverse proxy.
func WithProxyOptions(opts ...proxy.Option) Option {
	return optionFunc(func(o *options) {
		o.proxyOptions = opts
	})
}
