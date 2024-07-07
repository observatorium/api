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

// UpstreamOptions represents the options of the upstream TLS configuration
// this structure contains the certificates and the watchers if the certificate/ca watchers are enabled.
type UpstreamOptions struct {
	cert         *stdtls.Certificate
	ca           []byte
	certReloader *rbacproxytls.CertReloader
	caReloader   *caWatcher
}

// NewUpstreamOptions create a new UpstreamOptions, if interval is nil, the watcher will not be enabled.
func NewUpstreamOptions(ctx context.Context, upstreamCertFile, upstreamKeyFile, upstreamCAFile string,
	interval *time.Duration, logger log.Logger, g run.Group) (*UpstreamOptions, error) {

	// reload enabled
	if interval != nil {
		return newWithWatchers(ctx, upstreamCertFile, upstreamKeyFile, upstreamCAFile, *interval, logger, g)
	}

	return newNoWatchers(upstreamCertFile, upstreamKeyFile, upstreamCAFile)
}

func newWithWatchers(ctx context.Context, upstreamCertFile, upstreamKeyFile, upstreamCAFile string,
	interval time.Duration, logger log.Logger, g run.Group) (*UpstreamOptions, error) {
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
	pool *x509.CertPool) (*caWatcher, error) {
	caReloader, err := newCAWatcher(upstreamCAFile, logger, interval, pool)
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

// hasCA determine if the CA was specified.
func (uo *UpstreamOptions) hasCA() bool {
	return len(uo.ca) != 0 || uo.caReloader != nil
}

// hasCA determine if the hasUpstreamCerts were specified.
func (uo *UpstreamOptions) hasUpstreamCerts() bool {
	return uo.cert != nil || uo.certReloader != nil
}

// hasCA determine if the CA watcher is enabled.
func (uo *UpstreamOptions) isCAReloadEnabled() bool {
	return uo.caReloader != nil
}

// hasCA determine if the certificate watcher is enabled.
func (uo *UpstreamOptions) isCertReloaderEnabled() bool {
	return uo.certReloader != nil
}

// NewClientConfig returns a tls config for the reverse proxy handling if an upstream CA is given.
// this will transform TLS UpstreamOptions to a tls.Config native TLS golang structure, if the watchers are enabled
// it will override the GetClientCertificate function.
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
