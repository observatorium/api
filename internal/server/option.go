package server

import (
	"net/url"
	"time"

	"github.com/observatorium/observatorium/internal/proxy"
)

type options struct {
	gracePeriod          time.Duration
	timeout              time.Duration
	metricsUIEndpoint    *url.URL
	metricsReadEndpoint  *url.URL
	metricsWriteEndpoint *url.URL
	disableWrite         bool
	disableRead          bool
	profile              bool
	listen               string

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

// WithdisableWrite TODO
func WithDisableWrite(e bool) Option {
	return optionFunc(func(o *options) {
		o.disableWrite = e
	})
}

// WithDisableRead TODO
func WithDisableRead(e bool) Option {
	return optionFunc(func(o *options) {
		o.disableRead = e
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
