package server

import (
	"net/url"
	"time"

	"github.com/observatorium/observatorium/internal/proxy"
)

type options struct {
	gracePeriod               time.Duration
	timeout                   time.Duration
	metricsReadEndpoint       *url.URL
	metricsQueryEndpoint      *url.URL
	metricsQueryRangeEndpoint *url.URL
	metricsUIEndpoint         *url.URL
	metricsWriteEndpoint      *url.URL
	profile                   bool
	listen                    string

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

// WithMetricReadEndpoint TODO
func WithMetricReadEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsReadEndpoint = u
	})
}

// WithMetricQueryEndpoint TODO
func WithMetricQueryEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsQueryEndpoint = u
	})
}

// WithMetricQueryEndpoint TODO
func WithMetricQueryRangeEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsQueryRangeEndpoint = u
	})
}

// WithMetricUIEndpoint TODO
func WithMetricUIEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsUIEndpoint = u
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
