package authentication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/efficientgo/core/backoff"
	"github.com/go-chi/chi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/httperr"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// OIDCAuthenticatorType represents the oidc authentication provider type.
const OIDCAuthenticatorType = "oidc"

func init() {
	onboardNewProvider(OIDCAuthenticatorType, newOIDCAuthenticator)
}

// oidcConfig represents the oidc authenticator config.
type oidcConfig struct {
	ClientID      string `json:"clientID"`
	ClientSecret  string `json:"clientSecret"`
	GroupClaim    string `json:"groupClaim"`
	IssuerRawCA   []byte `json:"issuerCA"`
	IssuerCAPath  string `json:"issuerCAPath"`
	issuerCA      *x509.Certificate
	IssuerURL     string `json:"issuerURL"`
	RedirectURL   string `json:"redirectURL"`
	UsernameClaim string `json:"usernameClaim"`
}

type oidcAuthenticator struct {
	tenant       string
	logger       log.Logger
	config       oidcConfig
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	client       *http.Client
	cookieName   string
	redirectURL  string
	oauth2Config oauth2.Config
	handler      http.Handler
}

func newOIDCAuthenticator(c map[string]interface{}, tenant string,
	registrationRetryCount *prometheus.CounterVec, logger log.Logger) (Provider, error) {
	var config oidcConfig

	const (
		loginRoute    = "/login"
		callbackRoute = "/callback"
		handlerPrefix = "/oidc/{tenant}"
	)

	ctx := context.Background()

	err := mapstructure.Decode(c, &config)
	if err != nil {
		return nil, err
	}

	if len(config.IssuerURL) == 0 {
		return nil, fmt.Errorf("issuerURL is required")
	}

	if config.IssuerCAPath != "" {
		IssuerRawCA, err := os.ReadFile(config.IssuerCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read issuer ca file: %s", err.Error())
		}

		config.IssuerRawCA = IssuerRawCA
	}

	if len(config.IssuerRawCA) != 0 {
		block, _ := pem.Decode(config.IssuerRawCA)
		if block == nil {
			return nil, fmt.Errorf("failed to parse issuer CA certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer certificate: %s", err.Error())
		}

		config.issuerCA = cert
	}

	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if config.issuerCA != nil {
		t.TLSClientConfig = &tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		t.TLSClientConfig.RootCAs.AddCert(config.issuerCA)
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: t,
	}

	provider := newOIDCProvider(oidc.ClientContext(ctx, client), tenant, client, config.IssuerURL, registrationRetryCount, logger)

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{"openid", "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	oidcProvider := &oidcAuthenticator{
		tenant:       tenant,
		logger:       logger,
		config:       config,
		oauth2Config: oauth2Config,
		provider:     provider,
		verifier:     verifier,
		client:       client,
		cookieName:   fmt.Sprintf("observatorium_%s", tenant),
		redirectURL:  path.Join("/", tenant),
	}

	r := chi.NewRouter()
	r.Handle(loginRoute, otelhttp.WithRouteTag(handlerPrefix+loginRoute, oidcProvider.oidcLoginHandler(&oauth2Config)))
	r.Handle(callbackRoute, otelhttp.WithRouteTag(handlerPrefix+callbackRoute, oidcProvider.oidcCallBackHandler()))
	oidcProvider.handler = r

	return oidcProvider, nil
}

func newOIDCProvider(ctx context.Context, tenant string, client *http.Client, issuerURL string,
	registrationRetryCount *prometheus.CounterVec, logger log.Logger) *oidc.Provider {
	var provider *oidc.Provider

	var err error

	b := backoff.New(ctx, backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 0, // Retry indefinitely.
	})

	for b.Reset(); b.Ongoing(); {
		provider, err = oidc.NewProvider(oidc.ClientContext(ctx, client), issuerURL)
		if err != nil {
			level.Error(logger).Log(
				"tenant", tenant,
				"msg", fmt.Sprintf("failed to initialize authenticator %s after %d retries: %s",
					OIDCAuthenticatorType, b.NumRetries(), err))
			registrationRetryCount.WithLabelValues(tenant, OIDCAuthenticatorType).Inc()
			b.Wait()

			continue
		}

		break
	}

	return provider
}

func (a oidcAuthenticator) oidcLoginHandler(oauth2Config *oauth2.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusSeeOther)
	})
}

func (a oidcAuthenticator) oidcCallBackHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.ClientContext(r.Context(), a.client)

		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			msg := fmt.Sprintf("%s: %s", errMsg, desc)
			level.Debug(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusBadRequest)
			return
		}

		queryCode := r.URL.Query().Get("code")
		if queryCode == "" {
			const msg = "no code in request"
			level.Debug(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusBadRequest)
			return
		}
		queryState := r.URL.Query().Get("state")
		if queryState != state {
			const msg = "incorrect state in request"
			level.Debug(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusBadRequest)
			return
		}

		token, err := a.oauth2Config.Exchange(ctx, queryCode)
		if err != nil {
			msg := fmt.Sprintf("failed to get token: %v", err)
			level.Warn(a.logger).Log("msg", msg, "err", err)
			httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			const msg = "no id_token in token response"
			level.Warn(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
			return
		}

		_, err = a.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			msg := fmt.Sprintf("failed to verify ID token: %v", err)
			level.Warn(a.logger).Log("msg", msg)
			httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    a.cookieName,
			Value:   rawIDToken,
			Path:    "/",
			Expires: token.Expiry,
		})

		http.Redirect(w, r, a.redirectURL, http.StatusFound)
	})
}

func (a oidcAuthenticator) Handler() (string, http.Handler) {
	return "/oidc/{tenant}", a.handler
}

//nolint:gocognit
func (a oidcAuthenticator) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			authorizationHeader := r.Header.Get("Authorization")
			if authorizationHeader != "" {
				authorization := strings.Split(authorizationHeader, " ")
				if len(authorization) != 2 {
					const msg = "invalid Authorization header"
					level.Debug(a.logger).Log("msg", msg)
					httperr.PrometheusAPIError(w, msg, http.StatusUnauthorized)
					return
				}

				token = authorization[1]
			} else {
				cookie, err := r.Cookie(a.cookieName)
				if err != nil {
					tenant, ok := GetTenant(r.Context())
					if !ok {
						const msg = "error finding tenant"
						level.Warn(a.logger).Log("msg", msg)
						httperr.PrometheusAPIError(w, msg, http.StatusInternalServerError)
						return
					}
					// Redirect users to the OIDC login
					w.Header().Set("Location", path.Join("/oidc", tenant, "/login"))
					httperr.PrometheusAPIError(w, "failed to find token", http.StatusFound)
					return
				}
				token = cookie.Value
			}

			ctx, msg, code, _ := a.checkAuth(r.Context(), token)
			if code != http.StatusOK {
				httperr.PrometheusAPIError(w, msg, code)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

//nolint:gocognit
func (a oidcAuthenticator) GRPCMiddleware() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		var token string

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return ctx, status.Error(codes.Internal, "metadata error")
		}

		authorizationHeaders := md.Get("Authorization")
		if len(authorizationHeaders) > 0 {
			if authorizationHeaders[0] != "" {
				authorization := strings.Split(authorizationHeaders[0], " ")
				if len(authorization) != 2 {
					return ctx, status.Error(codes.InvalidArgument, "invalid Authorization header")
				}

				token = authorization[1]
			}
		}

		ctx, msg, _, code := a.checkAuth(ctx, token)
		if code != codes.OK {
			return ctx, status.Error(code, msg)
		}

		return ctx, nil
	})
}

func (a oidcAuthenticator) checkAuth(ctx context.Context, token string) (context.Context, string, int, codes.Code) {
	idToken, err := a.verifier.Verify(oidc.ClientContext(ctx, a.client), token)
	if err != nil {
		const msg = "failed to verify ID token"

		// Verification failure can be anything from an OIDC connection problem, bogus bearer token,
		// or expired token.  The HTTP version surfaced this to the user, which we don't want to do.
		// We log it to allow the possibility of debugging this.
		level.Debug(a.logger).Log("msg", msg, "err", err)

		// The original HTTP implementation returned StatusInternalServerError.
		// For gRPC we return Unknown, as we can't really
		// be sure the problem is internal and not deserving Unauthenticated or InvalidArgument.
		return ctx, msg, http.StatusInternalServerError, codes.Unknown
	}

	sub := idToken.Subject

	if a.config.UsernameClaim != "" {
		claims := map[string]interface{}{}
		if err := idToken.Claims(&claims); err != nil {
			const msg = "failed to read claims"

			level.Warn(a.logger).Log("msg", msg, "err", err)

			return ctx, msg, http.StatusInternalServerError, codes.Internal
		}

		rawUsername, ok := claims[a.config.UsernameClaim]
		if !ok {
			const msg = "username cannot be empty"

			level.Debug(a.logger).Log("msg", msg)

			return ctx, msg, http.StatusBadRequest, codes.PermissionDenied
		}

		username, ok := rawUsername.(string)
		if !ok || username == "" {
			const msg = "invalid username claim value"

			level.Debug(a.logger).Log("msg", msg)

			return ctx, msg, http.StatusBadRequest, codes.PermissionDenied
		}

		sub = username
	}

	ctx = context.WithValue(ctx, subjectKey, sub)

	if a.config.GroupClaim != "" {
		var groups []string

		claims := map[string]interface{}{}
		if err := idToken.Claims(&claims); err != nil {
			const msg = "failed to read claims"

			level.Warn(a.logger).Log("msg", msg, "err", err)

			return ctx, msg, http.StatusInternalServerError, codes.Internal
		}

		rawGroup, ok := claims[a.config.GroupClaim]
		if !ok {
			const msg = "group cannot be empty"

			level.Debug(a.logger).Log("msg", msg)

			return ctx, msg, http.StatusBadRequest, codes.PermissionDenied
		}

		switch v := rawGroup.(type) {
		case string:
			groups = append(groups, v)
		case []string:
			groups = v
		case []interface{}:
			groups = make([]string, 0, len(v))
			for i := range v {
				groups = append(groups, fmt.Sprintf("%v", v[i]))
			}
		}

		ctx = context.WithValue(ctx, groupsKey, groups)
	}

	return ctx, "", http.StatusOK, codes.OK
}
