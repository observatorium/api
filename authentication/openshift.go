package authentication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/efficientgo/tools/core/pkg/backoff"
	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/observatorium/api/authentication/openshift"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

//nolint:gochecknoglobals
const (
	jwtSigningKey    = "ILoveObservatorium"
	defaultJWTExpiry = 15 * time.Minute

	defaultOAuthScopeUserInfo        = "user:info"
	defaultOAuthScopeUserCheckAccess = "user:check-access"
	defaultOAuthScopeListProjects    = "user:list-projects"
)

// OpenShiftClaims represents the JWT registered claims amended by
// an extra fields for groups.
type OpenShiftClaims struct {
	Groups      []string `json:"groups"`
	AccessToken string   `json:"accessToken"`
	jwt.RegisteredClaims
}

// TenantOpenShiftAuthConfig represents the OpenShift authentication configuration for a single tenant.
type TenantOpenShiftAuthConfig struct {
	Tenant string

	OpenShiftAuthConfig
}

// OpenShiftAuthConfig represents a generic OpenShift authentication configuration.
type OpenShiftAuthConfig struct {
	KubeConfigPath   string
	ServiceAccount   string
	ServiceAccountCA []byte
	RedirectURL      string
	CookieSecret     string
}

// OpenShiftAuthHandlers holds handlers and a set of middlewares for all
// tenants that is able to authenticate requests and provide the
// authorization code grant flow for users.
type OpenShiftAuthHandlers struct {
	mtx         sync.RWMutex
	handlers    map[string]http.Handler
	middlewares map[string]Middleware
	logger      log.Logger
	retryCount  *prometheus.CounterVec
}

// NewOpenShiftAuthHandlers instantiates OAuth2 handlers.
func NewOpenShiftAuthHandlers(l log.Logger, retryCount *prometheus.CounterVec) *OpenShiftAuthHandlers {
	return &OpenShiftAuthHandlers{
		handlers:    make(map[string]http.Handler),
		middlewares: make(map[string]Middleware),
		logger:      l,
		retryCount:  retryCount,
	}
}

// AddOpenShiftAuthForTenant adds a new handler and middleware for a new tenant, based on
// the tenant OpenShiftAuth configuration. If a connection with the OpenShift auth provider
// cannot be established, the method will retry to connect with an increasing backoff.
func (oh *OpenShiftAuthHandlers) AddOpenShiftAuthForTenant(prefix string, config TenantOpenShiftAuthConfig) {
	const (
		loginRoute    = "/login"
		callbackRoute = "/callback"
	)

	ctx := context.Background()
	b := backoff.New(ctx, backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 0, // Retry indefinitely.
	})

	go func() {
		r := chi.NewRouter()

		for b.Reset(); b.Ongoing(); {
			p, err := NewOpenShiftAuthProvider(
				oh.logger,
				getCookieForTenant(config.Tenant),
				config.OpenShiftAuthConfig,
			)
			if err != nil {
				level.Warn(oh.logger).Log("msg", "failed to instantiate OpenShift provider for tenant", "tenant", config.Tenant, "error", err)
				oh.retryCount.WithLabelValues(config.Tenant, providerOpenShift).Inc()
				b.Wait()
				continue
			}

			r.Handle(loginRoute, otelhttp.WithRouteTag(prefix+loginRoute, p.LoginHandler()))
			r.Handle(callbackRoute, otelhttp.WithRouteTag(prefix+callbackRoute, p.CallbackHandler()))

			oh.mtx.Lock()
			oh.handlers[config.Tenant] = r
			oh.middlewares[config.Tenant] = p.Middleware()
			oh.mtx.Unlock()

			level.Info(oh.logger).Log("msg", "OpenShift provider instantiated for tenant", "tenant", config.Tenant)

			return
		}
	}()
}

// GetTenantMiddleware an OpenShift auth middleware for the specified tenant, if found.
func (oh *OpenShiftAuthHandlers) GetTenantMiddleware(tenant string) (Middleware, bool) {
	oh.mtx.RLock()
	mw, ok := oh.middlewares[tenant]
	oh.mtx.RUnlock()

	return mw, ok
}

// Router returns a router with handlers for all registered tenants.
func (oh *OpenShiftAuthHandlers) Router() *chi.Mux {
	r := chi.NewRouter()
	r.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := GetTenant(r.Context())
		const msg = "error finding tenant"
		if !ok {
			level.Warn(oh.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		oh.mtx.RLock()
		h, ok := oh.handlers[tenant]
		oh.mtx.RUnlock()
		if !ok {
			level.Debug(oh.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))

	return r
}

// OpenShiftAuthProvider is an opinionated way to create login and callback
// handlers as well as HTTP middlewares to authenticate requests
// against the provider.
type OpenShiftAuthProvider struct {
	logger        log.Logger
	cipher        *openshift.Cipher
	client        *http.Client
	config        OpenShiftAuthConfig
	authenticator authenticator.Request
	oauth2Config  oauth2.Config
	cookieName    string
}

// NewOpenShiftAuthProvider creates a new OAuth2Provider.
func NewOpenShiftAuthProvider(logger log.Logger, cookieName string, config OpenShiftAuthConfig) (*OpenShiftAuthProvider, error) {
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

	if config.ServiceAccountCA != nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(config.ServiceAccountCA)

		t.TLSClientConfig = &tls.Config{
			RootCAs: pool,
		}
	}

	client := &http.Client{
		Jar:       http.DefaultClient.Jar,
		Timeout:   5 * time.Second,
		Transport: t,
	}

	authURL, tokenURL, err := openshift.DiscoverOAuth(client)
	if err != nil {
		return nil, errors.Wrap(err, "unable to auto discover OpenShift OAuth endpoints")
	}

	clientID, clientSecret, err := openshift.DiscoverCredentials(config.ServiceAccount)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read serviceaccount credentials")
	}

	authOpts := openshift.DelegatingAuthenticationOptions{
		RemoteKubeConfigFile: config.KubeConfigPath,
		CacheTTL:             2 * time.Minute,
		ClientCert: openshift.ClientCertAuthenticationOptions{
			ClientCA: openshift.ServiceAccountCAPath,
		},
		RequestHeader: openshift.RequestHeaderAuthenticationOptions{
			ClientCAFile: openshift.ServiceAccountCAPath,
		},
		SkipInClusterLookup: true,
		WebhookRetryBackoff: &wait.Backoff{ // Default APIserver options
			Duration: 500 * time.Millisecond,
			Factor:   1.5,
			Jitter:   0.2,
			Steps:    5,
		},
	}

	authConfig, err := authOpts.ToAuthenticationConfig()
	if err != nil {
		return nil, errors.Wrap(err, "unable to create auth config")
	}

	authenticator, _, err := authConfig.New()
	if err != nil {
		return nil, errors.Wrap(err, "unable to initialize authenticator")
	}

	var cipher *openshift.Cipher
	if config.CookieSecret != "" {
		cipher, err = openshift.NewCipher([]byte(config.CookieSecret))
		if err != nil {
			return nil, errors.Wrap(err, "unable to initialize cookie cipher")
		}
	}

	return &OpenShiftAuthProvider{
		authenticator: authenticator,
		logger:        logger,
		cipher:        cipher,
		client:        client,
		config:        config,
		cookieName:    cookieName,
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   authURL.String(),
				TokenURL:  tokenURL.String(),
				AuthStyle: oauth2.AuthStyleInParams,
			},
			Scopes: []string{
				defaultOAuthScopeUserInfo,
				defaultOAuthScopeUserCheckAccess,
				defaultOAuthScopeListProjects,
			},
			RedirectURL: config.RedirectURL,
		},
	}, nil
}

// Middleware creates an HTTP middleware, that can be used to wrap a
// http.Handler to authenticate requests for it.
func (p *OpenShiftAuthProvider) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to authenticate the request using the default OpenShift authenticator first.
			// The authenticator is using internally either a TokenReview request to the APIserver to
			// validate provided bearer tokens or validates the provided client certificates using the
			// cluster CA.
			// Following use cases apply here:
			// 1. When a service calls the obs-api providing its serviceaccount token in the authorization header
			// 2. When a service calls the obs-api providing client certificates signed by the cluster CA
			res, ok, _ := p.authenticator.AuthenticateRequest(r)
			if ok {
				ctx := context.WithValue(r.Context(), SubjectKey, res.User.GetName())
				ctx = context.WithValue(ctx, GroupsKey, res.User.GetGroups())

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			level.Info(p.logger).Log("msg", "fallback to read cookie, no serviceaccount bearer token or mTLS certs provided")

			// Next try to authenticate a user via cookie. This case applies
			// when users went through the OAuth2 flow supported by this
			// provider. Observatorium stores a self-signed JWT token on a
			// cookie per tenant to identify the subject of incoming requests.
			cookie, err := r.Cookie(p.cookieName)
			if err != nil {
				tenant, ok := GetTenant(r.Context())
				if !ok {
					const msg = "error finding tenant"
					level.Warn(p.logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
				}
				// Redirect users to the oauth2 login
				w.Header().Set("Location", path.Join("/openshift", tenant, "/login?route=", r.URL.Path))
				http.Error(w, "failed to find token", http.StatusFound)
				return
			}

			jwtToken, err := jwt.ParseWithClaims(cookie.Value, &OpenShiftClaims{}, func(t *jwt.Token) (interface{}, error) {
				return []byte(jwtSigningKey), nil
			})
			if err != nil {
				msg := errors.Wrap(err, "failed to parse jwt token: %s").Error()
				level.Warn(p.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			if !jwtToken.Valid {
				const msg = "failed to authenticate"
				level.Warn(p.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			claims, ok := jwtToken.Claims.(*OpenShiftClaims)
			if !ok {
				const msg = "failed to read claims"
				level.Warn(p.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			ctx := context.WithValue(r.Context(), SubjectKey, claims.Subject)
			ctx = context.WithValue(ctx, GroupsKey, claims.Groups)

			var accessToken string
			if p.config.CookieSecret != "" {
				accessToken, err = p.cipher.Decrypt(claims.AccessToken)
				if err != nil {
					msg := errors.Wrap(err, "failed to decrypt acess token").Error()
					level.Warn(p.logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
				}

				ctx = context.WithValue(ctx, AccessTokenKey, accessToken)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoginHandler returns a http.Handler, that starts the OAuth2 flow with the
// OpenShift OAuth server.
func (p *OpenShiftAuthProvider) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := url.Parse(p.oauth2Config.Endpoint.AuthURL)
		if err != nil {
			const msg = "failed to parse authorization endpoint URL"
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		queryRoute := r.URL.Query().Get("route")
		if queryRoute == "" {
			const msg = "incorrect route in request"
			level.Debug(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		params := url.Values{}
		redirectURI := fmt.Sprintf("%s?route=%s", p.config.RedirectURL, queryRoute)
		params.Set("redirect_uri", redirectURI)
		params.Set("approval_prompt", "force")
		params.Set("scope", strings.Join(p.oauth2Config.Scopes, " "))
		params.Set("client_id", p.oauth2Config.ClientID)
		params.Set("response_type", "code")
		params.Set("state", state)
		u.RawQuery = params.Encode()

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})
}

// CallbackHandler returns a http.Handler, that is meant to be redirected to
// after the OpenShift OAuth server has authenticated the user. On success a
// cookie with a self-signed JWT token will be stored per tenant on the user
// client to re-authenticate the user on subsequent calls. The provided JWT
// is a security measurment to circumvent storing the access token on the
// client side. Furthermore the JWT token has a validity of 15 minutes per
// default.
func (p *OpenShiftAuthProvider) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			msg := fmt.Sprintf("%s: %s", errMsg, desc)
			level.Debug(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		queryCode := r.URL.Query().Get("code")
		if queryCode == "" {
			const msg = "no code in request"
			level.Debug(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		queryState := r.URL.Query().Get("state")
		if queryState != state {
			const msg = "incorrect state in request"
			level.Debug(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		queryRoute := r.URL.Query().Get("route")
		if queryRoute == "" {
			const msg = "incorrect route in request"
			level.Debug(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		ctx := context.WithValue(r.Context(), oauth2.HTTPClient, p.client)

		// Exchange code for auth token.
		redirectURI := fmt.Sprintf("%s?route=%s", p.config.RedirectURL, queryRoute)
		o2c := oauth2.Config{
			ClientID:     p.oauth2Config.ClientID,
			ClientSecret: p.oauth2Config.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   p.oauth2Config.Endpoint.AuthURL,
				TokenURL:  p.oauth2Config.Endpoint.TokenURL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			Scopes:      p.oauth2Config.Scopes,
			RedirectURL: redirectURI,
		}

		token, err := o2c.Exchange(ctx, queryCode)
		if err != nil {
			msg := fmt.Sprintf("failed to get token: %v", err)
			level.Warn(p.logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		if !token.Valid() {
			const msg = "invalid token provided"
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		// Create a fake request for the k8s authenticator using
		// the auth token to do a token review and retrieve the
		// user info, i.e. subject name and groups.
		req, err := http.NewRequest(http.MethodGet, queryRoute, nil)
		if err != nil {
			const msg = "invalid request to the apiserver"
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

		res, ok, err := p.authenticator.AuthenticateRequest(req)
		if err != nil {
			msg := fmt.Sprintf("failed to authenticate redirect request: %s", err)
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		if !ok {
			const msg = "failed to authenticate redirect request"
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		var encToken string
		if p.config.CookieSecret != "" {
			encToken, err = p.cipher.Encrypt(token.AccessToken)
			if err != nil {
				const msg = "failed to encrypt access token"
				level.Warn(p.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
		}

		// Create a custom JWT token for observatorium browser client
		// users to identify the session.
		issueAt := time.Now()
		expiry := time.Now().Add(defaultJWTExpiry)
		jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &OpenShiftClaims{
			Groups:      res.User.GetGroups(),
			AccessToken: encToken,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "observatorium",
				ExpiresAt: jwt.NewNumericDate(expiry),
				IssuedAt:  jwt.NewNumericDate(issueAt),
				Subject:   res.User.GetName(),
			},
		})

		str, err := jwtToken.SignedString([]byte(jwtSigningKey))
		if err != nil {
			msg := fmt.Sprintf("failed to sign jwt token: %s", err)
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    p.cookieName,
			Value:   str,
			Path:    "/",
			Expires: expiry,
		})

		http.Redirect(w, r, queryRoute, http.StatusFound)
	})
}
