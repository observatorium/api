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

// WithBufferCount sets the buffer count option for the reverse proxy.
func WithBufferCount(i int) Option {
	return optionFunc(func(o *options) {
		o.bufferCount = i
	})
}

// WithBufferSizeBytes sets the buffer size bytes option for the reverse proxy.
func WithBufferSizeBytes(i int) Option {
	return optionFunc(func(o *options) {
		o.bufferSizeBytes = i
	})
}

// WithFlushInterval sets the flush interval option for the reverse proxy.
func WithFlushInterval(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.flushInterval = t
	})
}

// WithMaxIdsConns sets the max idle conns for the underlying reverse proxy transport.
func WithMaxIdsConns(i int) Option {
	return optionFunc(func(o *options) {
		o.maxIdleConns = i
	})
}

// WithIdleConnTimeout sets the idle timeout duration for the underlying reverse proxy transport.
func WithIdleConnTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.idleConnTimeout = t
	})
}

// WithTimeout sets the timeout duration for the underlying reverse proxy connection.
func WithTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.timeout = t
	})
}

// WithKeepAlive sets the keep alive duration for the underlying reverse proxy connection.
func WithKeepAlive(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.keepAlive = t
	})
}

// WithTLSHandshakeTimeout sets the max TLS handshake timeout duration for the underlying reverse proxy transport.
func WithTLSHandshakeTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.tlsHandshakeTimeout = t
	})
}

// WithExpectContinueTimeout sets the max expected continue timeout duration for the underlying reverse proxy transport.
func WithExpectContinueTimeout(t time.Duration) Option {
	return optionFunc(func(o *options) {
		o.expectContinueTimeout = t
	})
}
