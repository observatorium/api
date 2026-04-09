package authentication

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/observatorium/api/httperr"
)

// MTLSAuthenticatorType represents the mTLS authentication provider type.
const MTLSAuthenticatorType = "mtls"

func init() {
	onboardNewProvider(MTLSAuthenticatorType, newMTLSAuthenticator)
}

type mTLSConfig struct {
	RawCA        []byte        `json:"ca"`
	CAPath       string        `json:"caPath"`
	Paths        []PathPattern `json:"paths,omitempty"`
	CAs          []*x509.Certificate
	pathMatchers []PathMatcher
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
			rest  = rawCA
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

	for _, pathPattern := range config.Paths {
		operator := pathPattern.Operator
		if operator == "" {
			operator = OperatorMatches
		}

		if operator != OperatorMatches && operator != OperatorNotMatches {
			return nil, fmt.Errorf("invalid mTLS path operator %q, must be %q or %q", operator, OperatorMatches, OperatorNotMatches)
		}

		matcher, err := regexp.Compile(pathPattern.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile mTLS path pattern %q: %v", pathPattern.Pattern, err)
		}

		config.pathMatchers = append(config.pathMatchers, PathMatcher{
			Operator: operator,
			Regex:    matcher,
		})
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
			level.Debug(a.logger).Log("msg", "mTLS middleware processing", "path", r.URL.Path, "tenant", a.tenant, "numPatterns", len(a.config.pathMatchers))

			// Check if mTLS is required for this path
			if len(a.config.pathMatchers) > 0 {
				shouldEnforceMTLS := false

				for _, matcher := range a.config.pathMatchers {
					regexMatches := matcher.Regex.MatchString(r.URL.Path)
					level.Debug(a.logger).Log("msg", "mTLS path pattern check", "path", r.URL.Path, "operator", matcher.Operator, "pattern", matcher.Regex.String(), "matches", regexMatches)

					if matcher.Operator == OperatorMatches && regexMatches {
						level.Debug(a.logger).Log("msg", "mTLS positive match - enforcing", "path", r.URL.Path)
						shouldEnforceMTLS = true
						break
					} else if matcher.Operator == OperatorNotMatches && !regexMatches {
						// Negative match - enforce mTLS (path does NOT match pattern)
						level.Debug(a.logger).Log("msg", "mTLS negative match - enforcing", "path", r.URL.Path)
						shouldEnforceMTLS = true
						break
					}
				}

				level.Debug(a.logger).Log("msg", "mTLS enforcement decision", "path", r.URL.Path, "shouldEnforceMTLS", shouldEnforceMTLS)
				if !shouldEnforceMTLS {
					level.Debug(a.logger).Log("msg", "mTLS skipping enforcement", "path", r.URL.Path)
					next.ServeHTTP(w, r)
					return
				}
			}

			level.Debug(a.logger).Log("msg", "mTLS enforcing authentication", "path", r.URL.Path, "tenant", a.tenant)
			if r.TLS == nil {
				httperr.PrometheusAPIError(w, "mTLS required but no TLS connection", http.StatusBadRequest)
				return
			}

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

			// Mark request as successfully authenticated
			ctx = SetAuthenticated(ctx)
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
