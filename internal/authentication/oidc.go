package authentication

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/go-chi/chi"
	"golang.org/x/oauth2"
)

const (
	state = "I love Observatorium"
)

// OIDCConfig represents the OIDC configuration for a single tenant.
type OIDCConfig struct {
	Tenant        string
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
func NewOIDC(configs ...OIDCConfig) (http.Handler, map[string]Middleware, error) {
	handlers := map[string]http.Handler{}
	middlewares := map[string]Middleware{}

	for _, c := range configs {
		h, m, err := newProvider(c)
		if err != nil {
			return nil, nil, err
		}

		handlers[c.Tenant] = h
		middlewares[c.Tenant] = m
	}

	r := chi.NewRouter()
	r.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := GetTenant(r.Context())
		if !ok {
			http.Error(w, "error finding tenant", http.StatusInternalServerError)
			return
		}
		h, ok := handlers[tenant]
		if !ok {
			http.Error(w, "error finding tenant", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))

	return r, middlewares, nil
}

func newProvider(config OIDCConfig) (http.Handler, Middleware, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	provider, err := oidc.NewProvider(context.TODO(), config.IssuerURL)
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
					http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
					return
				}

				token = authorization[1]
			} else {
				cookie, err := r.Cookie(getCookieForTenant(config.Tenant))
				if err != nil {
					http.Error(w, "failed to find token", http.StatusUnauthorized)
					return
				}
				token = cookie.Value
			}

			idToken, err := verifier.Verify(r.Context(), token)
			if err != nil {
				http.Error(w, "failed to authenticate", http.StatusBadRequest)
				return
			}

			sub := idToken.Subject
			if config.UsernameClaim != "" {
				claims := map[string]interface{}{}
				if err := idToken.Claims(&claims); err != nil {
					http.Error(w, "failed to read claims", http.StatusInternalServerError)
					return
				}
				rawUsername, ok := claims[config.UsernameClaim]
				if !ok {
					http.Error(w, "username cannot be empty", http.StatusBadRequest)
					return
				}
				username, ok := rawUsername.(string)
				if !ok || username == "" {
					http.Error(w, "invalid username claim value", http.StatusBadRequest)
					return
				}
				sub = username
			}
			ctx := context.WithValue(r.Context(), subjectKey, sub)

			if config.GroupClaim != "" {
				var groups []string
				claims := map[string]interface{}{}
				if err := idToken.Claims(&claims); err != nil {
					http.Error(w, "failed to read claims", http.StatusInternalServerError)
					return
				}
				rawGroup, ok := claims[config.GroupClaim]
				if !ok {
					http.Error(w, "group cannot be empty", http.StatusBadRequest)
					return
				}
				switch v := rawGroup.(type) {
				case string:
					groups = append(groups, v)
				case []string:
					groups = v
				}
				ctx = context.WithValue(r.Context(), groupsKey, groups)
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
			http.Error(w, fmt.Sprintf("%s: %s", errMsg, desc), http.StatusBadRequest)
			return
		}

		queryCode := r.URL.Query().Get("code")
		if queryCode == "" {
			http.Error(w, "no code in request", http.StatusBadRequest)
			return
		}
		queryState := r.URL.Query().Get("state")
		if queryState != state {
			http.Error(w, "incorrect state in request", http.StatusBadRequest)
			return
		}

		token, err := oauth2Config.Exchange(ctx, queryCode)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in token response", http.StatusInternalServerError)
			return
		}

		_, err = verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to verify ID token: %v", err), http.StatusInternalServerError)
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
