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
	"time"

	"github.com/efficientgo/tools/core/pkg/backoff"
	"github.com/go-chi/chi"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/golang-jwt/jwt/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/authentication/openshift"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

const OpenShiftAuthenticatorType = "openshift"

//nolint:gochecknoglobals
const (
	jwtSigningKey    = "ILoveObservatorium"
	defaultJWTExpiry = 15 * time.Minute

	defaultOAuthScopeUserInfo        = "user:info"
	defaultOAuthScopeUserCheckAccess = "user:check-access"
	defaultOAuthScopeListProjects    = "user:list-projects"
)

//nolint:gochecknoinits
func init() {
	// authenticatorFactories[OpenShiftAuthenticatorType] = newOpenshiftAuthenticator
	onboardNewProvider(OpenShiftAuthenticatorType, newOpenshiftAuthenticator)
}

// OpenShiftClaims represents the JWT registered claims amended by
// an extra fields for groups.
type OpenShiftClaims struct {
	Groups      []string `json:"groups"`
	AccessToken string   `json:"accessToken"`
	jwt.RegisteredClaims
}

type openshiftAuthenticatorConfig struct {
	KubeConfigPath   string `json:"kubeconfig"`
	ServiceAccount   string `json:"serviceAccount"`
	RedirectURL      string `json:"redirectURL"`
	CookieSecret     string `json:"cookieSecret"`
	ServiceAccountCA []byte
}

type OpenShiftAuthenticator struct {
	tenant        string
	logger        log.Logger
	cipher        *openshift.Cipher
	client        *http.Client
	config        openshiftAuthenticatorConfig
	authenticator authenticator.Request
	oauth2Config  oauth2.Config
	cookieName    string
	handler       http.Handler
}

//nolint:funlen
func newOpenshiftAuthenticator(c map[string]interface{}, tenant string,
	registrationRetryCount *prometheus.CounterVec, logger log.Logger) (Provider, error) {
	var config openshiftAuthenticatorConfig

	const (
		loginRoute    = "/login"
		callbackRoute = "/callback"
		handlerPrefix = "/openshift/{tenant}"
	)

	err := mapstructure.Decode(c, &config)
	if err != nil {
		return nil, err
	}

	// Load CAs once for all tenants using openshift authentication.
	ocpCA, err := openshift.GetServiceAccountCACert()
	if err != nil {
		return nil, fmt.Errorf("failed to load serviceccount ca certificate %s", err.Error())
	}

	config.ServiceAccountCA = ocpCA

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

	ctx := context.Background()
	b := backoff.New(ctx, backoff.Config{
		Min:        500 * time.Millisecond,
		Max:        5 * time.Second,
		MaxRetries: 0, // Retry indefinitely.
	})

	var authURL *url.URL

	var tokenURL *url.URL

	for b.Reset(); b.Ongoing(); {
		authURL, tokenURL, err = openshift.DiscoverOAuth(client)
		if err != nil {
			level.Error(logger).Log(
				"tenant", tenant,
				"msg", errors.Wrap(err, "unable to auto discover OpenShift OAuth endpoints"))
			registrationRetryCount.WithLabelValues(tenant, OpenShiftAuthenticatorType).Inc()
			b.Wait()

			continue
		}

		break
	}

	var clientID string

	var clientSecret string

	for b.Reset(); b.Ongoing(); {
		clientID, clientSecret, err = openshift.DiscoverCredentials(config.ServiceAccount)
		if err != nil {
			level.Error(logger).Log(
				"tenant", tenant,
				"msg", errors.Wrap(err, "unable to read serviceaccount credentials"))
			registrationRetryCount.WithLabelValues(tenant, OpenShiftAuthenticatorType).Inc()
			b.Wait()

			continue
		}

		break
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

	osAuthenticator := OpenShiftAuthenticator{
		tenant:        tenant,
		authenticator: authenticator,
		logger:        logger,
		cipher:        cipher,
		client:        client,
		config:        config,
		cookieName:    fmt.Sprintf("observatorium_%s", tenant),
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
	}

	r := chi.NewRouter()
	r.Handle(loginRoute, otelhttp.WithRouteTag(handlerPrefix+loginRoute, osAuthenticator.openshiftLoginHandler()))
	r.Handle(callbackRoute, otelhttp.WithRouteTag(handlerPrefix+callbackRoute, osAuthenticator.openshiftCallbackHandler()))
	osAuthenticator.handler = r

	return osAuthenticator, nil
}

func (a OpenShiftAuthenticator) openshiftLoginHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := url.Parse(a.oauth2Config.Endpoint.AuthURL)
		if err != nil {
			const msg = "failed to parse authorization endpoint URL"
			level.Warn(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		queryRoute := r.URL.Query().Get("route")
		if queryRoute == "" {
			const msg = "incorrect route in request"
			level.Debug(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		params := url.Values{}
		redirectURI := fmt.Sprintf("%s?route=%s", a.config.RedirectURL, queryRoute)
		params.Set("redirect_uri", redirectURI)
		params.Set("approval_prompt", "force")
		params.Set("scope", strings.Join(a.oauth2Config.Scopes, " "))
		params.Set("client_id", a.oauth2Config.ClientID)
		params.Set("response_type", "code")
		params.Set("state", state)
		u.RawQuery = params.Encode()

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})
}

func (a OpenShiftAuthenticator) openshiftCallbackHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			msg := fmt.Sprintf("%s: %s", errMsg, desc)
			level.Debug(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		queryCode := r.URL.Query().Get("code")
		if queryCode == "" {
			const msg = "no code in request"
			level.Debug(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		queryState := r.URL.Query().Get("state")
		if queryState != state {
			const msg = "incorrect state in request"
			level.Debug(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		queryRoute := r.URL.Query().Get("route")
		if queryRoute == "" {
			const msg = "incorrect route in request"
			level.Debug(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)

		// Exchange code for auth token.
		redirectURI := fmt.Sprintf("%s?route=%s", a.config.RedirectURL, queryRoute)
		o2c := oauth2.Config{
			ClientID:     a.oauth2Config.ClientID,
			ClientSecret: a.oauth2Config.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   a.oauth2Config.Endpoint.AuthURL,
				TokenURL:  a.oauth2Config.Endpoint.TokenURL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			Scopes:      a.oauth2Config.Scopes,
			RedirectURL: redirectURI,
		}

		token, err := o2c.Exchange(ctx, queryCode)
		if err != nil {
			msg := fmt.Sprintf("failed to get token: %v", err)
			level.Warn(a.logger).Log("msg", msg, "err", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		if !token.Valid() {
			const msg = "invalid token provided"
			level.Warn(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		// Create a fake request for the k8s authenticator using
		// the auth token to do a token review and retrieve the
		// user info, i.e. subject name and groups.
		req, err := http.NewRequest(http.MethodGet, queryRoute, nil)
		if err != nil {
			const msg = "invalid request to the apiserver"
			level.Warn(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

		res, ok, err := a.authenticator.AuthenticateRequest(req)
		if err != nil {
			msg := fmt.Sprintf("failed to authenticate redirect request: %s", err)
			level.Warn(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		if !ok {
			const msg = "failed to authenticate redirect request"
			level.Warn(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}

		var encToken string
		if a.config.CookieSecret != "" {
			encToken, err = a.cipher.Encrypt(token.AccessToken)
			if err != nil {
				const msg = "failed to encrypt access token"
				level.Warn(a.logger).Log("msg", msg)
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
			level.Warn(a.logger).Log("msg", msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    a.cookieName,
			Value:   str,
			Path:    "/",
			Expires: expiry,
		})

		http.Redirect(w, r, queryRoute, http.StatusFound)
	})
}

func (a OpenShiftAuthenticator) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to authenticate the request using the default OpenShift authenticator first.
			// The authenticator is using internally either a TokenReview request to the APIserver to
			// validate provided bearer tokens or validates the provided client certificates using the
			// cluster CA.
			// Following use cases apply here:
			// 1. When a service calls the obs-api providing its serviceaccount token in the authorization header
			// 2. When a service calls the obs-api providing client certificates signed by the cluster CA
			res, ok, _ := a.authenticator.AuthenticateRequest(r)
			if ok {
				ctx := context.WithValue(r.Context(), subjectKey, res.User.GetName())
				ctx = context.WithValue(ctx, groupsKey, res.User.GetGroups())

				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			level.Info(a.logger).Log("msg", "fallback to read cookie, no serviceaccount bearer token or mTLS certs provided")

			// Next try to authenticate a user via cookie. This case applies
			// when users went through the OAuth2 flow supported by this
			// provider. Observatorium stores a self-signed JWT token on a
			// cookie per tenant to identify the subject of incoming requests.
			cookie, err := r.Cookie(a.cookieName)
			if err != nil {
				tenant, ok := GetTenant(r.Context())
				if !ok {
					const msg = "error finding tenant"
					level.Warn(a.logger).Log("msg", msg)
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
				level.Warn(a.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			if !jwtToken.Valid {
				const msg = "failed to authenticate"
				level.Warn(a.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			claims, ok := jwtToken.Claims.(*OpenShiftClaims)
			if !ok {
				const msg = "failed to read claims"
				level.Warn(a.logger).Log("msg", msg)
				http.Error(w, msg, http.StatusBadRequest)
				return
			}

			ctx := context.WithValue(r.Context(), subjectKey, claims.Subject)
			ctx = context.WithValue(ctx, groupsKey, claims.Groups)

			var accessToken string
			if a.config.CookieSecret != "" {
				accessToken, err = a.cipher.Decrypt(claims.AccessToken)
				if err != nil {
					msg := errors.Wrap(err, "failed to decrypt acess token").Error()
					level.Warn(a.logger).Log("msg", msg)
					http.Error(w, msg, http.StatusBadRequest)
					return
				}

				ctx = context.WithValue(ctx, accessTokenKey, accessToken)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (a OpenShiftAuthenticator) Handler() (string, http.Handler) {
	return "/openshift/{tenant}", a.handler
}
