package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/oklog/run"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certutil "k8s.io/client-go/util/cert"

	"github.com/observatorium/api/logger"
)

func newSelfSignedCert(hostname string) (string, string, func(), error) {
	var err error
	certBytes, keyBytes, err := certutil.GenerateSelfSignedCertKey(hostname, nil, nil)
	if err != nil {
		return "", "", func() {}, fmt.Errorf("generation of self signed cert and key failed: %w", err)
	}

	certPath, err := writeTempFile("cert", certBytes)
	if err != nil {
		return "", "", func() {}, fmt.Errorf("error writing cert data: %w", err)
	}

	keyPath, err := writeTempFile("key", keyBytes)
	if err != nil {
		return "", "", func() {
			_ = os.Remove(certPath)
		}, fmt.Errorf("error writing key data: %w", err)
	}

	return certPath, keyPath, func() {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
	}, nil
}

func TestUpstreamOptions_NewClientConfigNoTimeInteval(t *testing.T) {
	ca, caPath, cleanCA, err := newSelfSignedCA("ok")
	defer cleanCA()
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	certPath, keyPath, cleanCerts, err := newSelfSignedCert("local")
	defer cleanCerts()
	require.NoError(t, err)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	var g run.Group

	logger := logger.NewLogger("info", logger.LogFormatLogfmt, "")

	tests := []struct {
		name                 string
		caPath               string
		certPath             string
		keyPath              string
		expectedErr          bool
		expectedNilCfg       bool
		expectedRootCA       *x509.CertPool
		expectedCertificates []tls.Certificate
	}{
		{
			name:                 "all enabled",
			caPath:               caPath,
			certPath:             certPath,
			keyPath:              keyPath,
			expectedRootCA:       caPool,
			expectedCertificates: []tls.Certificate{cert},
			expectedNilCfg:       false,
		},
		{
			name:           "cert/key empty",
			caPath:         caPath,
			expectedRootCA: caPool,
			expectedNilCfg: false,
		},
		{
			name:                 "ca empty",
			certPath:             certPath,
			keyPath:              keyPath,
			expectedCertificates: []tls.Certificate{cert},
			expectedNilCfg:       true,
		},
		{
			name:           "both empty",
			expectedNilCfg: true,
		},
		{
			name:           "invalid CA",
			caPath:         "/nowhere",
			certPath:       certPath,
			keyPath:        keyPath,
			expectedNilCfg: true,
			expectedErr:    true,
		},
		{
			name:           "invalid cert",
			caPath:         caPath,
			certPath:       "/nowhere",
			keyPath:        keyPath,
			expectedNilCfg: true,
			expectedErr:    true,
		},
		{
			name:           "invalid key",
			caPath:         caPath,
			certPath:       certPath,
			keyPath:        "/nowhere",
			expectedNilCfg: true,
			expectedErr:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := NewUpstreamOptions(
				context.Background(),
				tc.certPath, tc.keyPath, tc.caPath, nil, logger, g)

			if tc.expectedErr {
				assert.Error(t, err)
				assert.Nil(t, opts)
			} else {
				assert.NoError(t, err)

				cfg := opts.NewClientConfig()
				if tc.expectedNilCfg {
					assert.Nil(t, cfg)
				} else {
					assert.Equal(t, tc.expectedCertificates, cfg.Certificates)
					if tc.expectedRootCA != nil {
						assert.True(t, tc.expectedRootCA.Equal(cfg.RootCAs))
					} else {
						assert.Nil(t, cfg.RootCAs)
					}
				}
			}
		})
	}
}

func TestUpstreamOptions_NewClientConfigTimeInterval(t *testing.T) {
	ca, caPath, cleanCA, err := newSelfSignedCA("ok")
	defer cleanCA()
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	certPath, keyPath, cleanCerts, err := newSelfSignedCert("local")
	defer cleanCerts()
	require.NoError(t, err)

	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	var g run.Group
	logger := logger.NewLogger("info", logger.LogFormatLogfmt, "")

	tests := []struct {
		name                    string
		caPath                  string
		certPath                string
		keyPath                 string
		expectedErr             bool
		expectedNilCfg          bool
		setGetClientCertificate bool
		expectedRootCA          *x509.CertPool
		expectedCertificates    []tls.Certificate
	}{
		{
			name:                    "all enabled",
			caPath:                  caPath,
			certPath:                certPath,
			keyPath:                 keyPath,
			expectedNilCfg:          false,
			setGetClientCertificate: true,
			expectedRootCA:          caPool,
		},
		{
			name:                    "cert/key empty",
			caPath:                  caPath,
			expectedRootCA:          caPool,
			setGetClientCertificate: false,
			expectedNilCfg:          false,
		},
		{
			name:           "ca empty",
			certPath:       certPath,
			keyPath:        keyPath,
			expectedNilCfg: true,
		},
		{
			name:           "both empty",
			expectedNilCfg: true,
		},
		{
			name:           "invalid CA",
			caPath:         "/nowhere",
			certPath:       certPath,
			keyPath:        keyPath,
			expectedNilCfg: true,
			expectedErr:    true,
		},
		{
			name:           "invalid cert",
			caPath:         caPath,
			certPath:       "/nowhere",
			keyPath:        keyPath,
			expectedNilCfg: true,
			expectedErr:    true,
		},
		{
			name:           "invalid key",
			caPath:         caPath,
			certPath:       certPath,
			keyPath:        "/nowhere",
			expectedNilCfg: true,
			expectedErr:    true,
		},
	}

	interval := time.Second * 1

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := NewUpstreamOptions(
				context.Background(),
				tc.certPath, tc.keyPath, tc.caPath, &interval, logger, g)

			if tc.expectedErr {
				assert.Error(t, err)
				assert.Nil(t, opts)
			} else {
				assert.NoError(t, err)

				cfg := opts.NewClientConfig()
				if tc.expectedNilCfg {
					assert.Nil(t, cfg)
				} else {
					assert.Equal(t, tc.expectedCertificates, cfg.Certificates)
					if tc.expectedRootCA != nil {
						assert.True(t, tc.expectedRootCA.Equal(cfg.RootCAs))
					} else {
						assert.Nil(t, cfg.RootCAs)
					}

					if tc.setGetClientCertificate {
						assert.NotNil(t, cfg.GetClientCertificate)
					} else {
						assert.Nil(t, cfg.GetClientCertificate)
					}
				}
			}
		})
	}
}
