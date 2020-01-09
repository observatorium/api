package proxy

import "time"

type options struct {
	bufferCount     int
	bufferSizeBytes int
	flushInterval   time.Duration
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
