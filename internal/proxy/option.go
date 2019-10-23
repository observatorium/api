package proxy

type options struct {
	bufferCount     int
	bufferSizeBytes int
}

// Option overrides behavior of Proxy.
type Option interface {
	apply(*options)
}

type optionFunc func(*options)

func (f optionFunc) apply(o *options) {
	f(o)
}

func WithBufferCount(i int) Option {
	return optionFunc(func(o *options) {
		o.bufferCount = i
	})
}

func WithBufferSizeBytes(i int) Option {
	return optionFunc(func(o *options) {
		o.bufferSizeBytes = i
	})
}
