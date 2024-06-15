package tls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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

type CAWatcher struct {
	caMutex         sync.RWMutex
	certPool        *x509.CertPool
	logger          log.Logger
	fileHashContent string
	CAPath          string
	interval        time.Duration
}

func NewCAWatcher(CAPath string, logger log.Logger, interval time.Duration) (*CAWatcher, error) {
	w := &CAWatcher{
		CAPath:   CAPath,
		logger:   logger,
		certPool: x509.NewCertPool(),
		interval: interval,
	}
	err := w.loadCA()
	return w, err
}

func (w *CAWatcher) Watch(ctx context.Context) error {
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

func (w *CAWatcher) loadCA() error {

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
		// prevent concurrent updates to the same certPool
		w.caMutex.Lock()
		defer w.caMutex.Unlock()

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			level.Error(w.logger).Log("failed to parse CA %s", w.CAPath)
			return err
		}
		w.certPool = certPool
	}
	return nil
}

// hashFile returns the SHA256 hash of the file.
func (w *CAWatcher) hashFile(file string) (string, error) {
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

func (w *CAWatcher) getClientConfig(original *tls.Config) (*tls.Config, error) {
	w.caMutex.RLock()
	defer w.caMutex.RUnlock()
	return &tls.Config{
		GetCertificate:       original.GetCertificate,
		GetClientCertificate: original.GetClientCertificate,
		MinVersion:           original.MinVersion,
		MaxVersion:           original.MaxVersion,
		NextProtos:           original.NextProtos,
		RootCAs:              w.certPool,
		ClientAuth:           original.ClientAuth,
	}, nil
}
