package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/observatorium/api/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certutil "k8s.io/client-go/util/cert"
)

func TestCertWatcher(t *testing.T) {
	logger := logger.NewLogger("info", logger.LogFormatLogfmt, "")
	reloadInterval := 2 * time.Second

	caA, caPathA, cleanupA, err := newSelfSignedCA("ok")
	defer cleanupA()
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	caPool.AddCert(caA)

	reloader, err := newCACertificateWatcher(caPathA, logger, reloadInterval, caPool)
	require.NoError(t, err)

	cancelContext, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		err := reloader.Watch(cancelContext)
		require.NoError(t, err)
		wg.Done()
	}()
	// Start watch loop

	// Generate new CA
	caB, caPathB, cleanupB, err := newSelfSignedCA("baz")
	defer cleanupB()
	require.NoError(t, err)

	cbPool := x509.NewCertPool()
	cbPool.AddCert(caB)
	err = swapCert(t, caPathA, caPathB)
	require.NoError(t, err)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caA)
	rootCAs.AddCert(caB)

	assert.Eventually(t, func() bool {
		return rootCAs.Equal(reloader.pool())

	}, 5*reloadInterval, reloadInterval)

	cancel()
	wg.Wait()

}

func newSelfSignedCA(hostname string) (*x509.Certificate, string, func(), error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", func() {}, fmt.Errorf("generation of private key failed: %v", err)
	}

	ca, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: hostname}, privKey)
	if err != nil {
		return nil, "", func() {}, fmt.Errorf("generation of certificate, failed: %v", err)
	}

	// Create a PEM block with the certificate
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	})

	certPath, err := writeTempFile("cert", pemBytes)
	if err != nil {
		return nil, "", func() {}, fmt.Errorf("error writing cert data: %v", err)
	}

	return ca, certPath, func() {
		_ = os.Remove(certPath)
	}, nil
}

func writeTempFile(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("error creating temp file: %v", err)
	}
	defer f.Close()

	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}

	if err != nil {
		return "", fmt.Errorf("error writing temporary file: %v", err)
	}

	return f.Name(), nil
}

func swapCert(t *testing.T, caPathA, caPathB string) error {
	t.Log("renaming", caPathB, "to", caPathA)
	if err := os.Rename(caPathB, caPathA); err != nil {
		return err
	}
	return nil
}
