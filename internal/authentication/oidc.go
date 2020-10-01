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
	"time"

	"github.com/coreos/go-oidc"
	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"golang.org/x/oauth2"
)

const (
	state = "I love Observatorium"
)

// OIDCConfig represents the OIDC configuration for a single tenant.
type OIDCConfig struct {
	Tenant        string
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

// NewOIDC creates a single http.Handler and a set of Middlewares for all
// tenants that is able to authenticate requests and provide the
// authorization code grant flow for users.
func NewOIDC(logger log.Logger, configs []OIDCConfig) (http.Handler, map[string]Middleware, []error) {
	handlers := map[string]http.Handler{}
	middlewares := map[string]Middleware{}
	warnings := make([]error, 0, len(configs))

	for _, c := range configs {
		h, m, err := newProvider(logger, c)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("failed to instantiate OIDC provider for tenant %q: %w", c.Tenant, err))
			continue
		}

		handlers[c.Tenant] = h
		middlewares[c.Tenant] = m
	}

	r := chi.NewRouter()
	r.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := GetTenant(r.Context())
		const msg = "error finding tenant"
		if !ok {
			level.Warn(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		h, ok := handlers[tenant]
		if !ok {
			level.Debug(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))

	return r, middlewares, warnings
}

func newProvider(logger log.Logger, config OIDCConfig) (http.Handler, Middleware, error) {
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
	provider, err := oidc.NewProvider(oidc.ClientContext(context.TODO(), client), config.IssuerURL)
	if err != nil {
		return nil, nil, err
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{"openid", "profile", "email", "groups"},
	}

	m := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			authorizationHeader := r.Header.Get("Authorization")
			if authorizationHeader != "" {
				authorization := strings.Split(authorizationHeader, " ")
				if len(authorization) != 2 {
					const msg = "invalid Authorization header"
					level.Debug(logger).Log("msg", msg)
					http.Error(w, msg, http.StatusUnauthorized)
					return
				}

				token = authorization[1]
			} else {
				cookie, err := r.Cookie(getCookieForTenant(config.Tenant))
				if err != nil {
					tenant, ok := GetTenant(r.Context())
					if !ok {
						const msg = "error finding tenant"
						level.Warn(logger).Log("msg", msg)
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

			idToken, err := verifier.Verify(oidc.ClientContext(r.Context(), client), token)
			if err != nil {
				const msg = "failed to authenticate"
				level.Debug(logger).Log("msg", msg, "err", err)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			sub := idToken.Subject
			if config.UsernameClaim != "" {
				claims := map[string]interface{}{}
				if err := idToken.Claims(&claims); err != nil {
					const msg = "failed to read claims"
					level.Warn(logger).Log("msg", msg, "err", err)
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
				rawUsername, ok := claims[config.UsernameClaim]
				if !ok {
					const msg = "username cannot be empty"
					level.Debug(logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
				}
				username, ok := rawUsername.(string)
				if !ok || username == "" {
					const msg = "invalid username claim value"
					level.Debug(logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
				}
				sub = username
			}
			ctx := context.WithValue(r.Context(), subjectKey, sub)

			if config.GroupClaim != "" {
				var groups []string
				claims := map[string]interface{}{}
				if err := idToken.Claims(&claims); err != nil {
					const msg = "failed to read claims"
					level.Warn(logger).Log("msg", msg, "err", err)
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
				rawGroup, ok := claims[config.GroupClaim]
				if !ok {
					const msg = "group cannot be empty"
					level.Debug(logger).Log("msg", msg)
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

	r := chi.NewRouter()
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		url := oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusSeeOther)
	})

	r.Get("/callback", func(w http.ResponseWriter, r *http.Request) {
		ctx := oidc.ClientContext(r.Context(), client)

		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			msg := fmt.Sprintf("%s: %s", errMsg, desc)
			level.Debug(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		queryCode := r.URL.Query().Get("code")
		if queryCode == "" {
			const msg = "no code in request"
			level.Debug(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		queryState := r.URL.Query().Get("state")
		if queryState != state {
			const msg = "incorrect state in request"
			level.Debug(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		token, err := oauth2Config.Exchange(ctx, queryCode)
		if err != nil {
			msg := fmt.Sprintf("failed to get token: %v", err)
			level.Warn(logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			const msg = "no id_token in token response"
			level.Warn(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		_, err = verifier.Verify(ctx, rawIDToken)
		if err != nil {
			msg := fmt.Sprintf("failed to verify ID token: %v", err)
			level.Warn(logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    getCookieForTenant(config.Tenant),
			Value:   rawIDToken,
			Path:    "/",
			Expires: token.Expiry,
		})

		http.Redirect(w, r, "/"+config.Tenant, http.StatusFound)
	})

	return r, m, nil
}

func getCookieForTenant(tenant string) string {
	return fmt.Sprintf("observatorium_%s", tenant)
}
