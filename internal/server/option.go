package server

import (
	"crypto/tls"
	"net/url"
	"time"

	"github.com/observatorium/observatorium/internal/proxy"
)

type options struct {
	gracePeriod time.Duration
	timeout     time.Duration
	tlsConfig   *tls.Config

	metricsUIEndpoint    *url.URL
	metricsReadEndpoint  *url.URL
	metricsWriteEndpoint *url.URL

	profile bool
	listen  string

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

// WithGracePeriod TODO
func WithGracePeriod(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.gracePeriod = t
	})
}

// WithListen TODO
func WithListen(s string) Option {
	return optionFunc(func(o *options) {
		o.listen = s
	})
}

// WithTimeout TODO
func WithTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.timeout = t
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

// WithMetricReadEndpoint TODO
func WithMetricReadEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsReadEndpoint = u
	})
}

// WithMetricWriteEndpoint TODO
func WithMetricWriteEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsWriteEndpoint = u
	})
}

// WithProfile TODO
func WithProfile(p bool) Option {
	return optionFunc(func(o *options) {
		o.profile = p
	})
}

// WithProxyOptions TODO
func WithProxyOptions(opts ...proxy.Option) Option {
	return optionFunc(func(o *options) {
		o.proxyOptions = opts
	})
}
