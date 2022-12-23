package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// NewClientConfig returns a tls config for the reverse proxy handling if an upstream CA is given.
func NewClientConfig(upstreamCA []byte, upstreamCert *tls.Certificate) *tls.Config {
	if len(upstreamCA) == 0 {
		return nil
	}

	cfg := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}
	cfg.RootCAs.AppendCertsFromPEM(upstreamCA)

	if upstreamCert != nil {
		cfg.Certificates = append(cfg.Certificates, *upstreamCert)
	}

	return cfg
}

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

	tlsMinVersion, err := parseTLSVersion(minVersion)
	if err != nil {
		return nil, fmt.Errorf("cannot parse TLS Version: %w", err)
	}

	tlsMaxVersion, err := parseTLSVersion(maxVersion)
	if err != nil {
		return nil, fmt.Errorf("cannot parse TLS Version: %w", err)
	}

	if tlsMinVersion > tlsMaxVersion {
		return nil, fmt.Errorf("TLS minimum version can not be greater than maximum version: %v > %v", tlsMinVersion, tlsMaxVersion)
	}

	cipherSuiteIDs, err := mapCipherNamesToIDs(cipherSuites)
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

func tlsCipherSuites() map[string]uint16 {
	cipherSuites := map[string]uint16{}

	for _, suite := range tls.CipherSuites() {
		cipherSuites[suite.Name] = suite.ID
	}
	for _, suite := range tls.InsecureCipherSuites() {
		cipherSuites[suite.Name] = suite.ID
	}

	return cipherSuites
}

func parseTLSVersion(rawTLSVersion string) (uint16, error) {
	switch rawTLSVersion {
	case "VersionTLS10":
		return tls.VersionTLS10, nil
	case "VersionTLS11":
		return tls.VersionTLS11, nil
	case "VersionTLS12":
		return tls.VersionTLS12, nil
	case "VersionTLS13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown TLSVersion: %s", rawTLSVersion)
	}
}

func mapCipherNamesToIDs(rawTLSCipherSuites []string) ([]uint16, error) {
	if rawTLSCipherSuites == nil {
		return nil, nil
	}

	cipherSuites := []uint16{}
	allCipherSuites := tlsCipherSuites()

	for _, name := range rawTLSCipherSuites {
		id, ok := allCipherSuites[name]
		if !ok {
			return nil, fmt.Errorf("unknown TLSCipherSuite: %s", name)
		}
		cipherSuites = append(cipherSuites, id)
	}

	return cipherSuites, nil
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
