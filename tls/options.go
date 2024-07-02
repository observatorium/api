package tls

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"os"
	"time"

	rbacproxytls "github.com/brancz/kube-rbac-proxy/pkg/tls"
	"github.com/go-kit/log"
	"github.com/oklog/run"
)

type UpstreamOptions struct {
	cert         *stdtls.Certificate
	ca           []byte
	certReloader *rbacproxytls.CertReloader
	caReloader   *CAWatcher
}

func NewUpstreamOptions(upstreamCertFile, upstreamKeyFile, upstreamCAFile string,
	interval *time.Duration, logger log.Logger, ctx context.Context, g run.Group) (*UpstreamOptions, error) {

	// reload enabled
	if interval != nil {
		return newWithWatchers(upstreamCertFile, upstreamKeyFile, upstreamCAFile, *interval, logger, ctx, g)
	}

	return newNoWatchers(upstreamCertFile, upstreamKeyFile, upstreamCAFile)
}

func newWithWatchers(upstreamCertFile, upstreamKeyFile, upstreamCAFile string,
	interval time.Duration, logger log.Logger, ctx context.Context, g run.Group) (*UpstreamOptions, error) {
	options := &UpstreamOptions{}

	if upstreamCertFile != "" && upstreamKeyFile != "" {
		certReloader, err := startCertReloader(ctx, g, upstreamCertFile, upstreamKeyFile, interval)
		if err != nil {
			return nil, err
		}
		options.certReloader = certReloader
	}
	if upstreamCAFile != "" {
		caPool := x509.NewCertPool()
		caReloader, err := startCAReloader(ctx, g, upstreamCAFile, interval, logger, caPool)
		if err != nil {
			return nil, err
		}
		options.caReloader = caReloader
	}
	return options, nil
}

func newNoWatchers(upstreamCertFile, upstreamKeyFile, upstreamCAFile string) (*UpstreamOptions, error) {
	options := &UpstreamOptions{}
	if upstreamCertFile != "" && upstreamKeyFile != "" {
		cert, err := stdtls.LoadX509KeyPair(upstreamCertFile, upstreamKeyFile)
		if err != nil {
			return nil, err
		}
		options.cert = &cert
	}

	if upstreamCAFile != "" {
		ca, err := os.ReadFile(upstreamCAFile)
		if err != nil {
			return nil, err
		}
		options.ca = ca
	}
	return options, nil
}

func startCertReloader(ctx context.Context, g run.Group,
	upstreamKeyFile, upstreamCertFile string, interval time.Duration) (*rbacproxytls.CertReloader, error) {
	certReloader, err := rbacproxytls.NewCertReloader(
		upstreamKeyFile,
		upstreamCertFile,
		interval,
	)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g.Add(func() error {
		return certReloader.Watch(ctx)
	}, func(error) {
		cancel()
	})
	return certReloader, nil
}

func startCAReloader(ctx context.Context, g run.Group, upstreamCAFile string, interval time.Duration, logger log.Logger,
	pool *x509.CertPool) (*CAWatcher, error) {
	caReloader, err := NewCAWatcher(upstreamCAFile, logger, interval, pool)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	g.Add(func() error {
		return caReloader.Watch(ctx)
	}, func(error) {
		cancel()
	})
	return caReloader, nil
}

func (uo *UpstreamOptions) hasCA() bool {
	return len(uo.ca) != 0 || uo.caReloader != nil
}

func (uo *UpstreamOptions) hasUpstreamCerts() bool {
	return uo.cert != nil || uo.certReloader != nil
}

func (uo *UpstreamOptions) isCAReloadEnabled() bool {
	return uo.caReloader != nil
}

func (uo *UpstreamOptions) isCertReloaderEnabled() bool {
	return uo.certReloader != nil
}

// NewClientConfig returns a tls config for the reverse proxy handling if an upstream CA is given.
func (uo *UpstreamOptions) NewClientConfig() *stdtls.Config {
	if !uo.hasCA() {
		return nil
	}
	cfg := &stdtls.Config{}

	if uo.hasUpstreamCerts() {
		if uo.isCertReloaderEnabled() {
			cfg.GetClientCertificate = func(info *stdtls.CertificateRequestInfo) (*stdtls.Certificate, error) {
				return uo.certReloader.GetCertificate(nil)
			}
		} else {
			cfg.Certificates = append(cfg.Certificates, *uo.cert)
		}
	}

	if uo.isCAReloadEnabled() {
		cfg.RootCAs = uo.caReloader.pool()
	} else {
		cfg.RootCAs = x509.NewCertPool()
		cfg.RootCAs.AppendCertsFromPEM(uo.ca)
	}
	return cfg
}
