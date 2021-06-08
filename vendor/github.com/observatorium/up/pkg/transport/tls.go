package transport

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
)

const HTTPS = "https"

func newTLSConfig(logger log.Logger, certFile, keyFile, caCertFile string) (*tls.Config, error) {
	var certPool *x509.CertPool

	if caCertFile != "" {
		caPEM, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			return nil, errors.Wrap(err, "reading client CA")
		}

		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			return nil, errors.Wrap(err, "building client CA")
		}

		level.Info(logger).Log("msg", "TLS client using provided certificate pool")
	} else {
		var err error
		certPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrap(err, "reading system certificate pool")
		}

		level.Info(logger).Log("msg", "TLS client using system certificate pool")
	}

	tlsCfg := &tls.Config{RootCAs: certPool}

	if (keyFile != "") != (certFile != "") {
		return nil, errors.Errorf("both client key and certificate must be provided")
	}

	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, errors.Wrap(err, "client credentials")
		}

		tlsCfg.Certificates = []tls.Certificate{cert}

		level.Info(logger).Log("msg", "TLS client authentication enabled")
	}

	return tlsCfg, nil
}
