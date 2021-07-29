package authentication

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
)

// MTLSConfig represents the mTLS configuration for a single tenant.
type MTLSConfig struct {
	Tenant string
	CAs    []*x509.Certificate
}

// NewMTLS create Middleware for a tenant.
func NewMTLS(config MTLSConfig) (Middleware, error) {
	middleware := func(next http.Handler) http.Handler {
		caPool := x509.NewCertPool()

		for _, ca := range config.CAs {
			caPool.AddCert(ca)
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "no client certificate presented", http.StatusUnauthorized)
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
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
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
				http.Error(w, "could not determine subject", http.StatusBadRequest)
				return
			}
			ctx := context.WithValue(r.Context(), subjectKey, sub)

			// Add organizational units as groups.
			ctx = context.WithValue(ctx, groupsKey, r.TLS.PeerCertificates[0].Subject.OrganizationalUnit)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	if middleware == nil {
		err := fmt.Errorf("NO mTLS configuration is present")
		return nil, err
	}

	return middleware, nil
}
