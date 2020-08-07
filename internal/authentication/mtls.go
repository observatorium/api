package authentication

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
)

// MTLSConfig represents the mTLS configuration for a single tenant.
type MTLSConfig struct {
	Tenant string
	CA     *x509.Certificate
}

// NewMTLS creates a set of Middlewares for all specified tenants.
func NewMTLS(configs []MTLSConfig) map[string]Middleware {
	middlewares := map[string]Middleware{}

	for _, c := range configs {
		middlewares[c.Tenant] = func(next http.Handler) http.Handler {
			caPool := x509.NewCertPool()
			caPool.AddCert(c.CA)
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
	}

	return middlewares
}
