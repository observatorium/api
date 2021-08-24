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

	"github.com/coreos/go-oidc"
	"github.com/efficientgo/tools/core/pkg/backoff"
	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

const (
	state = "I love Observatorium"
)

// TenantOIDCConfig represents the OIDC configuration for a single tenant.
type TenantOIDCConfig struct {
	Tenant string

	OIDCConfig
}

// OIDCConfig represents a generic OIDC configuration.
type OIDCConfig struct {
	IssuerCA      *x509.Certificate
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	GroupClaim    string
	RedirectURL   string
	UsernameClaim string
}

// Middleware is a convenience type for functions that wrap http.Handlers.
type Middleware func(http.Handler) http.Handler

// OIDCHandlers holds handlers and a set of middlewares for all
// tenants that is able to authenticate requests and provide the
// authorization code grant flow for users.
type OIDCHandlers struct {
	mtx         sync.RWMutex
	handlers    map[string]http.Handler
	middlewares map[string]Middleware

	logger log.Logger
}

// NewOIDCHandlers instantiates OIDC handlers.
func NewOIDCHandlers(l log.Logger) *OIDCHandlers {
	return &OIDCHandlers{
		handlers:    make(map[string]http.Handler),
		middlewares: make(map[string]Middleware),
		logger:      l,
	}
}

// AddOIDCForTenant adds a new handler and middleware for a new tenant, based on
// the tenant OIDC configuration. If a connection with the OIDC provider
// cannot be established, the method will retry to connect with an increasing
// backoff.
func (oh *OIDCHandlers) AddOIDCForTenant(prefix string, config TenantOIDCConfig) {
	ctx := context.Background()
	b := backoff.New(ctx, backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 0, // retry indefinitely
	})

	go func() {
		for b.Reset(); b.Ongoing(); {
			p, err := NewProvider(ctx, oh.logger, getCookieForTenant(config.Tenant), "/"+config.Tenant, config.OIDCConfig)
			if err != nil {
				level.Warn(oh.logger).Log("msg", "failed to instantiate OIDC provider for tenant", "tenant", config.Tenant, "error", err)
				b.Wait()
				continue
			}

			r := chi.NewRouter()

			const (
				loginRoute    = "/login"
				callbackRoute = "/callback"
			)

			r.Handle(loginRoute, otelhttp.WithRouteTag(prefix+loginRoute, p.LoginHandler()))
			r.Handle(callbackRoute, otelhttp.WithRouteTag(prefix+callbackRoute, p.CallbackHandler()))

			oh.mtx.Lock()
			oh.handlers[config.Tenant] = r
			oh.middlewares[config.Tenant] = p.Middleware()
			oh.mtx.Unlock()

			level.Debug(oh.logger).Log("msg", "OIDC provider instantiated for tenant", "tenant", config.Tenant)
			return
		}
	}()
}

// Middlewares returns a collction of OIDC middlewares for all registered tenants.
func (oh *OIDCHandlers) Middlewares() map[string]Middleware {
	oh.mtx.RLock()
	defer oh.mtx.RUnlock()

	return oh.middlewares
}

// Router returns a router with handlers for all registered tenants.
func (oh *OIDCHandlers) Router() *chi.Mux {
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

func getCookieForTenant(tenant string) string {
	return fmt.Sprintf("observatorium_%s", tenant)
}

// OIDCProvider wraps the oidc.Provider in an opinionated way to create login
// and callback handlers as well as HTTP middlewares to authenticate requests
// against the provider.
type OIDCProvider struct {
	logger       log.Logger
	provider     *oidc.Provider
	client       *http.Client
	config       OIDCConfig
	cookieName   string
	redirectURL  string
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// NewProvider creates a new OIDCProvider.
func NewProvider(ctx context.Context, logger log.Logger, cookieName, redirectURL string, config OIDCConfig) (*OIDCProvider, error) {
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

	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), config.IssuerURL)
	if err != nil {
		return nil, err
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{"openid", "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	return &OIDCProvider{
		logger:       logger,
		provider:     provider,
		client:       client,
		config:       config,
		cookieName:   cookieName,
		redirectURL:  redirectURL,
		oauth2Config: oauth2Config,
		verifier:     verifier,
	}, nil
}

// OIDCProvider returns the internal oidc.Provider, this can be used to for
// example access the UserInfo function of the provider.
func (p *OIDCProvider) OIDCProvider() *oidc.Provider {
	return p.provider
}

// Middleware creates an HTTP middleware, that can be used to wrap a
// http.Handler to authenticate requests for it.
//nolint:gocognit
func (p *OIDCProvider) Middleware() Middleware {
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
					// Redirect users to the OIDC login
					w.Header().Set("Location", path.Join("/oidc", tenant, "/login"))
					http.Error(w, "failed to find token", http.StatusFound)
					return
				}
				token = cookie.Value
			}

			idToken, err := p.verifier.Verify(oidc.ClientContext(r.Context(), p.client), token)
			if err != nil {
				const msg = "failed to authenticate"
				level.Debug(p.logger).Log("msg", msg, "err", err)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			sub := idToken.Subject
			if p.config.UsernameClaim != "" {
				claims := map[string]interface{}{}
				if err := idToken.Claims(&claims); err != nil {
					const msg = "failed to read claims"
					level.Warn(p.logger).Log("msg", msg, "err", err)
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
				rawUsername, ok := claims[p.config.UsernameClaim]
				if !ok {
					const msg = "username cannot be empty"
					level.Debug(p.logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
				}
				username, ok := rawUsername.(string)
				if !ok || username == "" {
					const msg = "invalid username claim value"
					level.Debug(p.logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
				}
				sub = username
			}
			ctx := context.WithValue(r.Context(), subjectKey, sub)

			if p.config.GroupClaim != "" {
				var groups []string
				claims := map[string]interface{}{}
				if err := idToken.Claims(&claims); err != nil {
					const msg = "failed to read claims"
					level.Warn(p.logger).Log("msg", msg, "err", err)
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
				rawGroup, ok := claims[p.config.GroupClaim]
				if !ok {
					const msg = "group cannot be empty"
					level.Debug(p.logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
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

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoginHandler returns a http.Handler, that starts the OIDC flow.
func (p *OIDCProvider) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := p.oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusSeeOther)
	})
}

// CallbackHandler returns a http.Handler, that is meant to be redirected to
// after the provider has authenticated the user.
func (p *OIDCProvider) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.ClientContext(r.Context(), p.client)

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

		token, err := p.oauth2Config.Exchange(ctx, queryCode)
		if err != nil {
			msg := fmt.Sprintf("failed to get token: %v", err)
			level.Warn(p.logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			const msg = "no id_token in token response"
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		_, err = p.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			msg := fmt.Sprintf("failed to verify ID token: %v", err)
			level.Warn(p.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    p.cookieName,
			Value:   rawIDToken,
			Path:    "/",
			Expires: token.Expiry,
		})

		http.Redirect(w, r, p.redirectURL, http.StatusFound)
	})
}
