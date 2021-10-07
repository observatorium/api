package authentication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/efficientgo/tools/core/pkg/backoff"
	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

var (
	jwtSigningKey    = []byte("ILoveObservatorium")
	defaultJWTExpiry = 15 * time.Minute
)

// TenantOAuth2Config represents the OAuth2 configuration for a single tenant.
type TenantOAuth2Config struct {
	Tenant string

	OAuth2Config
}

// OAuth2Config represents a generic OAuth2 configuration.
type OAuth2Config struct {
	IssuerCA     *x509.Certificate
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// OAuth2Handlers holds handlers and a set of middlewares for all
// tenants that is able to authenticate requests and provide the
// authorization code grant flow for users.
type OAuth2Handlers struct {
	mtx         sync.RWMutex
	handlers    map[string]http.Handler
	middlewares map[string]Middleware

	logger log.Logger
	// retryCount *prometheus.CounterVec
}

// NewOAuth2Handlers instantiates OAuth2 handlers.
func NewOAuth2Handlers(l log.Logger, reg prometheus.Registerer) *OAuth2Handlers {
	// tenantsFailing := prometheus.NewCounterVec(prometheus.CounterOpts{
	//	Namespace: "observatorium",
	//	Subsystem: "api",
	//	Name:      "tenants_failed_registrations",
	//	Help:      "The number of failed OAuth2 provider instantiations.",
	// }, []string{"tenant"})

	// reg.MustRegister(tenantsFailing)

	return &OAuth2Handlers{
		handlers:    make(map[string]http.Handler),
		middlewares: make(map[string]Middleware),
		logger:      l,
		// retryCount:  tenantsFailing,
	}
}

// AddOAuth2ForTenant adds a new handler and middleware for a new tenant, based on
// the tenant OAuth2 configuration. If a connection with the OAuth2 provider
// cannot be established, the method will retry to connect with an increasing
// backoff.
func (oh *OAuth2Handlers) AddOAuth2ForTenant(prefix string, config TenantOAuth2Config) {
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
			p, err := NewOAuth2Provider(oh.logger, getCookieForTenant(config.Tenant), "/"+config.Tenant, config.OAuth2Config)
			if err != nil {
				// oh.retryCount.WithLabelValues(config.Tenant).Inc()
				b.Wait()
				continue
			}

			r.Handle(loginRoute, otelhttp.WithRouteTag(prefix+loginRoute, p.LoginHandler()))
			r.Handle(callbackRoute, otelhttp.WithRouteTag(prefix+callbackRoute, p.CallbackHandler()))

			oh.mtx.Lock()
			oh.handlers[config.Tenant] = r
			oh.middlewares[config.Tenant] = p.Middleware()
			oh.mtx.Unlock()

			level.Info(oh.logger).Log("msg", "OAuth2 provider instantiated for tenant", "tenant", config.Tenant)

			return
		}
	}()
}

// GetTenantMiddleware an OAuth2 middleware for the specified tenant, if found.
func (oh *OAuth2Handlers) GetTenantMiddleware(tenant string) (Middleware, bool) {
	oh.mtx.RLock()
	mw, ok := oh.middlewares[tenant]
	oh.mtx.RUnlock()

	return mw, ok
}

// Router returns a router with handlers for all registered tenants.
func (oh *OAuth2Handlers) Router() *chi.Mux {
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

// OAuth2Provider is an opinionated way to create login and callback
// handlers as well as HTTP middlewares to authenticate requests
// against the provider.
type OAuth2Provider struct {
	logger       log.Logger
	client       *http.Client
	config       OAuth2Config
	cookieName   string
	redirectURL  string
	oauth2Config oauth2.Config
}

// NewOAuth2Provider creates a new OAuth2Provider.
func NewOAuth2Provider(logger log.Logger, cookieName, redirectURL string, config OAuth2Config) (*OAuth2Provider, error) {
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
	if config.IssuerCA != nil {
		t.TLSClientConfig = &tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		t.TLSClientConfig.RootCAs.AddCert(config.IssuerCA)
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: t,
	}

	endpoint := oauth2.Endpoint{
		AuthURL:   config.AuthURL,
		TokenURL:  config.TokenURL,
		AuthStyle: oauth2.AuthStyleAutoDetect,
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{"profile", "email"}, // TODO Verify scopes
	}

	return &OAuth2Provider{
		logger:       logger,
		client:       client,
		config:       config,
		cookieName:   cookieName,
		redirectURL:  redirectURL,
		oauth2Config: oauth2Config,
	}, nil
}

// Middleware creates an HTTP middleware, that can be used to wrap a
// http.Handler to authenticate requests for it.
func (p *OAuth2Provider) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			authorizationHeader := r.Header.Get("Authorization")
			if authorizationHeader != "" {
				authorization := strings.Split(authorizationHeader, " ")
				if len(authorization) != 2 {
					const msg = "invalid Authorization header"
					level.Debug(p.logger).Log("msg", msg)
					http.Error(w, msg, http.StatusUnauthorized)
					return
				}

				token = authorization[1]
			} else {
				cookie, err := r.Cookie(p.cookieName)
				if err != nil {
					tenant, ok := GetTenant(r.Context())
					if !ok {
						const msg = "error finding tenant"
						level.Warn(p.logger).Log("msg", msg)
						http.Error(w, msg, http.StatusInternalServerError)
						return
					}
					// Redirect users to the oauth2 login
					w.Header().Set("Location", path.Join("/oauth2", tenant, "/login"))
					http.Error(w, "failed to find token", http.StatusFound)
					return
				}
				token = cookie.Value
			}

			if token == "" {
				msg := "invalid token provided"
				level.Warn(p.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
				return jwtSigningKey, nil
			})
			if err != nil {
				msg := fmt.Sprintf("failed to parse jwt token: %s", err)
				level.Warn(p.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			if !jwtToken.Valid {
				msg := "invalid jwt token provided"
				level.Warn(p.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// LoginHandler returns a http.Handler, that starts the OAuth2 flow.
func (p *OAuth2Provider) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := p.oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusSeeOther)
	})
}

// CallbackHandler returns a http.Handler, that is meant to be redirected to
// after the provider has authenticated the user.
func (p *OAuth2Provider) CallbackHandler() http.Handler {
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

		ctx := context.WithValue(r.Context(), oauth2.HTTPClient, p.client)

		token, err := p.oauth2Config.Exchange(ctx, queryCode)
		if err != nil {
			msg := fmt.Sprintf("failed to get token: %v", err)
			level.Warn(p.logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		if !token.Valid() {
			msg := "invalid token provided"
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.RegisteredClaims{
			Issuer:    "observatorium",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(defaultJWTExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		})

		str, err := jwtToken.SignedString(jwtSigningKey)
		if err != nil {
			msg := fmt.Sprintf("failed to sign jwt token: %s", err)
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    p.cookieName,
			Value:   str,
			Path:    "/",
			Expires: token.Expiry,
		})

		http.Redirect(w, r, p.redirectURL, http.StatusFound)
	})
}
