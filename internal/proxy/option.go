package proxy

import "time"

type options struct {
	bufferCount           int
	bufferSizeBytes       int
	maxIdleConns          int
	flushInterval         time.Duration
	timeout               time.Duration
	keepAlive             time.Duration
	idleConnTimeout       time.Duration
	tlsHandshakeTimeout   time.Duration
	expectContinueTimeout time.Duration
}

// Option overrides behavior of Proxy.
type Option interface {
	apply(*options)
}

type optionFunc func(*options)

func (f optionFunc) apply(o *options) {
	f(o)
}

// WithBufferCount TODO
func WithBufferCount(i int) Option {
	return optionFunc(func(o *options) {
		o.bufferCount = i
	})
}

// WithBufferSizeBytes TODO
func WithBufferSizeBytes(i int) Option {
	return optionFunc(func(o *options) {
		o.bufferSizeBytes = i
	})
}

// WithFlushInterval TODO
func WithFlushInterval(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.flushInterval = t
	})
}

// WithMaxIdsConns TODO
func WithMaxIdsConns(i int) Option {
	return optionFunc(func(o *options) {
		o.maxIdleConns = i
	})
}

// WithIdleConnTimeout TODO
func WithIdleConnTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.idleConnTimeout = t
	})
}

// WithTimeout TODO
func WithTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.timeout = t
	})
}

// WithKeepAlive TODO
func WithKeepAlive(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.keepAlive = t
	})
}

// WithTLSHandshakeTimeout TODO
func WithTLSHandshakeTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.tlsHandshakeTimeout = t
	})
}

// WithExpectContinueTimeout TODO
func WithExpectContinueTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.expectContinueTimeout = t
	})
}
