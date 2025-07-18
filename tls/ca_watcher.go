package tls

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// caCertificateWatcher poll for changes on the CA certificate file, if the CA change it will add it to the certificate Pool.
type caCertificateWatcher struct {
	mutex           sync.RWMutex
	certPool        *x509.CertPool
	logger          log.Logger
	fileHashContent string
	CAPath          string
	interval        time.Duration
}

// newCACertificateWatcher creates a new watcher for the CA file.
func newCACertificateWatcher(CAPath string, logger log.Logger, interval time.Duration, pool *x509.CertPool) (*caCertificateWatcher, error) {
	w := &caCertificateWatcher{
		CAPath:   CAPath,
		logger:   logger,
		certPool: pool,
		interval: interval,
	}
	err := w.loadCA()
	return w, err
}

// Watch for the changes on the certificate each interval, if the content changes
// a new certificate will be added to the pool.
func (w *caCertificateWatcher) Watch(ctx context.Context) error {
	var timer *time.Timer

	scheduleNext := func() {
		timer = time.NewTimer(w.interval)
	}
	scheduleNext()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			err := w.loadCA()
			if err != nil {
				return err
			}
			scheduleNext()
		}
	}
}

func (w *caCertificateWatcher) loadCA() error {
	hash, err := w.hashFile(w.CAPath)
	if err != nil {
		level.Error(w.logger).Log("unable to read the file", "error", err.Error())
		return err
	}

	// If file changed
	if w.fileHashContent != hash {
		// read content
		caPEM, err := os.ReadFile(filepath.Clean(w.CAPath))
		if err != nil {
			level.Error(w.logger).Log("failed to load CA %s: %w", w.CAPath, err)
			return err
		}
		w.mutex.Lock()
		defer w.mutex.Unlock()
		if !w.certPool.AppendCertsFromPEM(caPEM) {
			level.Error(w.logger).Log("failed to parse CA %s", w.CAPath)
			return err
		}
	}
	return nil
}

func (w *caCertificateWatcher) pool() *x509.CertPool {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	return w.certPool
}

// hashFile returns the SHA256 hash of the file.
func (w *caCertificateWatcher) hashFile(file string) (string, error) {
	f, err := os.Open(filepath.Clean(file))
	if err != nil {
		return "", err
	}

	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
