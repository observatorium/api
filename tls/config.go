package tls

import (
	"crypto/tls"
	"fmt"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// curveIDs maps supported key-exchange group names to crypto/tls CurveIDs.
// Both IANA names and Go crypto/tls constant names are accepted.
var curveIDs = map[string]tls.CurveID{
	// X25519 and the ML-KEM hybrids: IANA name == Go constant name.
	"X25519":             tls.X25519,
	"X25519MLKEM768":     tls.X25519MLKEM768,
	"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
	"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,

	// Classic EC curves: IANA name (preferred) and Go constant name (alias).
	"secp256r1": tls.CurveP256,
	"secp384r1": tls.CurveP384,
	"secp521r1": tls.CurveP521,
	"CurveP521": tls.CurveP521,
	"CurveP256": tls.CurveP256,
	"CurveP384": tls.CurveP384,
}

// NewServerConfig provides new server TLS configuration.
func NewServerConfig(logger log.Logger, certFile, keyFile, minVersion, maxVersion, clientAuthType string, cipherSuites, curvePreferences []string) (*tls.Config, error) {
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

	curvePreferenceIDs, err := mapCurveNamesToIDs(curvePreferences)
	if err != nil {
		return nil, fmt.Errorf("TLS curve preference name to ID conversion: %v", err)
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
		// If CurvePreferences is nil, a default list of secure curves is used.
		CurvePreferences: curvePreferenceIDs,
		ClientAuth:       tlsClientAuthType,
		MinVersion:       tlsMinVersion,
		MaxVersion:       tlsMaxVersion,
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

func mapCurveNamesToIDs(rawTLSCurvePreferences []string) ([]tls.CurveID, error) {
	if rawTLSCurvePreferences == nil {
		return nil, nil
	}

	curvePreferences := []tls.CurveID{}

	for _, name := range rawTLSCurvePreferences {
		id, ok := curveIDs[name]
		if !ok {
			return nil, fmt.Errorf("unknown TLSCurve: %s", name)
		}

		curvePreferences = append(curvePreferences, id)
	}

	return curvePreferences, nil
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
