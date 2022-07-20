package tls

import (
	"crypto/tls"
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"k8s.io/component-base/cli/flag"
)

// NewServerConfig provides new server TLS configuration.
func NewServerConfig(logger log.Logger, certFile, keyFile, minVersion, maxVersion, clientAuthType string, cipherSuites []string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		level.Info(logger).Log("msg", "TLS disabled; key and cert must be set to enable")

		return nil, nil
	}

	level.Info(logger).Log("msg", "enabling server side TLS")

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("server credentials: %w", err)
	}

	tlsMinVersion, err := flag.TLSVersion(minVersion)
	if err != nil {
		return nil, fmt.Errorf("TLS version invalid: %w", err)
	}

	tlsMaxVersion, err := flag.TLSVersion(maxVersion)
	if err != nil {
		return nil, fmt.Errorf("TLS version invalid: %w", err)
	}

	if tlsMinVersion > tlsMaxVersion {
		return nil, fmt.Errorf("TLS minimum version can not be greater than maximum version: %v > %v", tlsMinVersion, tlsMaxVersion)
	}

	cipherSuiteIDs, err := flag.TLSCipherSuites(cipherSuites)
	if err != nil {
		return nil, fmt.Errorf("TLS cipher suite name to ID conversion: %v", err)
	}

	tlsClientAuthType, err := parseClientAuthType(clientAuthType)
	if err != nil {
		return nil, fmt.Errorf("can not parse TLS Client authentication policy: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		// A list of supported cipher suites for TLS versions up to TLS 1.2.
		// If CipherSuites is nil, a default list of secure cipher suites is used.
		// Note that TLS 1.3 ciphersuites are not configurable.
		CipherSuites: cipherSuiteIDs,
		ClientAuth:   tlsClientAuthType,
		MinVersion:   tlsMinVersion,
		MaxVersion:   tlsMaxVersion,
	}

	return tlsCfg, nil
}

func parseClientAuthType(rawAuthType string) (tls.ClientAuthType, error) {
	switch rawAuthType {
	case "NoClientCert":
		return tls.NoClientCert, nil
	case "RequestClientCert":
		return tls.RequestClientCert, nil
	case "RequireAnyClientCert":
		return tls.RequireAnyClientCert, nil
	case "VerifyClientCertIfGiven":
		return tls.VerifyClientCertIfGiven, nil
	case "RequireAndVerifyClientCert":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return 0, fmt.Errorf("unknown ClientAuthType: %s", rawAuthType)
	}
}
