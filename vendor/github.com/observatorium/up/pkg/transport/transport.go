package transport

import (
	"net"
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/observatorium/up/pkg/options"
	"github.com/pkg/errors"
)

func NewTLSTransport(l log.Logger, tls options.TLS) (*http.Transport, error) {
	tlsConfig, err := newTLSConfig(l, tls.Cert, tls.Key, tls.CACert)
	if err != nil {
		return nil, errors.Wrap(err, "tls config")
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, //nolint:gomnd
			KeepAlive: 30 * time.Second, //nolint:gomnd
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,              //nolint:gomnd
		IdleConnTimeout:       90 * time.Second, //nolint:gomnd
		TLSHandshakeTimeout:   10 * time.Second, //nolint:gomnd
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}, nil
}
