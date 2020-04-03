package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"k8s.io/component-base/cli/flag"
)

// NewServerConfig provides new server TLS configuration.
func NewServerConfig(logger log.Logger, certFile, keyFile, clientCAFile, minVersion string, cipherSuites []string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		if clientCAFile != "" {
			return nil, errors.New("when a client CA is used a server key and certificate must also be provided")
		}

		level.Info(logger).Log("msg", "TLS disabled key and cert must be set to enable")

		return nil, nil
	}

	level.Info(logger).Log("msg", "enabling server side TLS")

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("server credentials: %w", err)
	}

	tlsCfg := &tls.Config{}
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	version, err := flag.TLSVersion(minVersion)
	if err != nil {
		return nil, fmt.Errorf("TLS version invalid: %w", err)
	}

	tlsCfg.MinVersion = version

	cipherSuiteIDs, err := flag.TLSCipherSuites(cipherSuites)
	if err != nil {
		return nil, fmt.Errorf("TLS cipher suite name to ID conversion: %v", err)
	}

	// A list of supported cipher suites for TLS versions up to TLS 1.2.
	// If CipherSuites is nil, a default list of secure cipher suites is used.
	// Note that TLS 1.3 ciphersuites are not configurable.
	tlsCfg.CipherSuites = cipherSuiteIDs

	if clientCAFile != "" {
		caPEM, err := ioutil.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading client CA: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("building client CA: %w", err)
		}

		tlsCfg.ClientCAs = certPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

		level.Info(logger).Log("msg", "server TLS client verification enabled")
	}

	return tlsCfg, nil
}
