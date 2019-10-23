package server

import (
	"net/url"
	"time"

	"github.com/observatorium/observatorium/internal/proxy"
)

type options struct {
	gracePeriod          time.Duration
	metricsQueryEndpoint *url.URL
	metricsWriteEndpoint *url.URL
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

func WithGracePeriod(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.gracePeriod = t
	})
}

func WithListen(s string) Option {
	return optionFunc(func(o *options) {
		o.listen = s
	})
}

func WithMetricQueryEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsQueryEndpoint = u
	})
}

func WithMetricWriteEndpoint(u *url.URL) Option {
	return optionFunc(func(o *options) {
		o.metricsWriteEndpoint = u
	})
}

func WithProfile(p bool) Option {
	return optionFunc(func(o *options) {
		o.profile = p
	})
}

func WithProxyOptions(opts ...proxy.Option) Option {
	return optionFunc(func(o *options) {
		o.proxyOptions = opts
	})
}
