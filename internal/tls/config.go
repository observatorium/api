package tls

import (
	"crypto/tls"
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"k8s.io/component-base/cli/flag"
)

// NewServerConfig provides new server TLS configuration.
func NewServerConfig(logger log.Logger, certFile, keyFile, minVersion string, cipherSuites []string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {

		level.Info(logger).Log("msg", "TLS disabled; key and cert must be set to enable")

		return nil, nil
	}

	level.Info(logger).Log("msg", "enabling server side TLS")

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("server credentials: %w", err)
	}

	version, err := flag.TLSVersion(minVersion)
	if err != nil {
		return nil, fmt.Errorf("TLS version invalid: %w", err)
	}

	cipherSuiteIDs, err := flag.TLSCipherSuites(cipherSuites)
	if err != nil {
		return nil, fmt.Errorf("TLS cipher suite name to ID conversion: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		// A list of supported cipher suites for TLS versions up to TLS 1.2.
		// If CipherSuites is nil, a default list of secure cipher suites is used.
		// Note that TLS 1.3 ciphersuites are not configurable.
		CipherSuites: cipherSuiteIDs,
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   version,
	}

	return tlsCfg, nil
}
