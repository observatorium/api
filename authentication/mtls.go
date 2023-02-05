package authentication

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/go-kit/log"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/httperr"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MTLSAuthenticatorType represents the mTLS authentication provider type.
const MTLSAuthenticatorType = "mtls"

func init() {
	onboardNewProvider(MTLSAuthenticatorType, newMTLSAuthenticator)
}

type mTLSConfig struct {
	RawCA  []byte `json:"ca"`
	CAPath string `json:"caPath"`
	CAs    []*x509.Certificate
}

type MTLSAuthenticator struct {
	tenant string
	logger log.Logger
	config *mTLSConfig
}

func newMTLSAuthenticator(c map[string]interface{}, tenant string, registrationRetryCount *prometheus.CounterVec, logger log.Logger) (Provider, error) {
	var config mTLSConfig

	err := mapstructure.Decode(c, &config)
	if err != nil {
		return nil, err
	}

	if config.CAPath != "" {
		rawCA, err := os.ReadFile(config.CAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read mTLS ca file: %s", err.Error())
		}

		config.RawCA = rawCA

		var (
			block *pem.Block
			rest  []byte = rawCA
			cert  *x509.Certificate
			cas   []*x509.Certificate
		)

		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				return nil, fmt.Errorf("failed to parse CA certificate PEM")
			}

			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
			}

			cas = append(cas, cert)

			if len(rest) == 0 {
				break
			}
		}

		config.CAs = cas
	}

	return MTLSAuthenticator{
		tenant: tenant,
		logger: logger,
		config: &config,
	}, nil
}

func (a MTLSAuthenticator) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caPool := x509.NewCertPool()
			for _, ca := range a.config.CAs {
				caPool.AddCert(ca)
			}

			if len(r.TLS.PeerCertificates) == 0 {
				httperr.PrometheusAPIError(w, "no client certificate presented", http.StatusUnauthorized)
				return
			}

			opts := x509.VerifyOptions{
				Roots:         caPool,
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}

			if len(r.TLS.PeerCertificates) > 1 {
				for _, cert := range r.TLS.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
			}

			if _, err := r.TLS.PeerCertificates[0].Verify(opts); err != nil {
				if errors.Is(err, x509.CertificateInvalidError{}) {
					httperr.PrometheusAPIError(w, err.Error(), http.StatusUnauthorized)
					return
				}
				httperr.PrometheusAPIError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			var sub string
			switch {
			case len(r.TLS.PeerCertificates[0].EmailAddresses) > 0:
				sub = r.TLS.PeerCertificates[0].EmailAddresses[0]
			case len(r.TLS.PeerCertificates[0].URIs) > 0:
				sub = r.TLS.PeerCertificates[0].URIs[0].String()
			case len(r.TLS.PeerCertificates[0].DNSNames) > 0:
				sub = r.TLS.PeerCertificates[0].DNSNames[0]
			case len(r.TLS.PeerCertificates[0].IPAddresses) > 0:
				sub = r.TLS.PeerCertificates[0].IPAddresses[0].String()
			default:
				httperr.PrometheusAPIError(w, "could not determine subject", http.StatusBadRequest)
				return
			}
			ctx := context.WithValue(r.Context(), subjectKey, sub)

			// Add organizational units as groups.
			ctx = context.WithValue(ctx, groupsKey, r.TLS.PeerCertificates[0].Subject.OrganizationalUnit)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (a MTLSAuthenticator) GRPCMiddleware() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		return ctx, status.Error(codes.Unimplemented, "internal error")
	})
}

func (a MTLSAuthenticator) Handler() (string, http.Handler) {
	return "", nil
}
