package authorization

import (
	"context"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/observatorium/api/authentication"
	"github.com/observatorium/api/httperr"
	"github.com/observatorium/api/rbac"
)

// contextKey to use when setting context values in the HTTP package.
type contextKey string

const (
	// authorizationDataKey is the key that holds the authorization response data
	// in a request context.
	authorizationDataKey contextKey = "authzData"

	// authorizationSelectorsKey is the key that holds the data about selectors present in the query.
	authorizationSelectorsKey contextKey = "authzQuerySelectors"
)

type SelectorsInfo struct {
	Selectors   map[string][]string
	HasWildcard bool
}

var (
	emptySelectorsInfo = &SelectorsInfo{
		Selectors: map[string][]string{},
	}
)

// GetData extracts the authz response data from provided context.
func GetData(ctx context.Context) (string, bool) {
	value := ctx.Value(authorizationDataKey)
	data, ok := value.(string)

	return data, ok
}

// WithData extends the provided context with the authz response data.
func WithData(ctx context.Context, data string) context.Context {
	return context.WithValue(ctx, authorizationDataKey, data)
}

// GetSelectorsInfo extracts the query namespaces from the provided context.
func GetSelectorsInfo(ctx context.Context) (*SelectorsInfo, bool) {
	value := ctx.Value(authorizationSelectorsKey)
	namespaces, ok := value.(*SelectorsInfo)

	return namespaces, ok
}

// WithSelectorsInfo extends the provided context with the query namespaces.
func WithSelectorsInfo(ctx context.Context, info *SelectorsInfo) context.Context {
	return context.WithValue(ctx, authorizationSelectorsKey, info)
}

// WithLogsStreamSelectorsExtractor returns a middleware that, when enabled, tries to extract
// stream selectors from queries or rules, so that they can be used in authorizing the request.
func WithLogsStreamSelectorsExtractor(logger log.Logger, selectorNames []string) func(http.Handler) http.Handler {
	enabled := len(selectorNames) > 0

	selectorNameMap := make(map[string]bool, len(selectorNames))
	for _, l := range selectorNames {
		selectorNameMap[l] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)

				return
			}

			selectorsInfo, err := extractLogStreamSelectors(selectorNameMap, r.URL.Query())
			if err != nil {
				// Don't error out, just warn about error and continue with empty selectorsInfo
				level.Warn(logger).Log("msg", err)
				selectorsInfo = emptySelectorsInfo
			}

			next.ServeHTTP(w, r.WithContext(WithSelectorsInfo(r.Context(), selectorsInfo)))
		})
	}
}

// WithAuthorizers returns a middleware that authorizes subjects taken from a request context
// for the given permission on the given resource for a tenant taken from a request context.
func WithAuthorizers(authorizers map[string]rbac.Authorizer, permission rbac.Permission, resource string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			tenant, ok := authentication.GetTenant(ctx)
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant", http.StatusInternalServerError)

				return
			}
			subject, ok := authentication.GetSubject(ctx)
			if !ok {
				httperr.PrometheusAPIError(w, "unknown subject", http.StatusUnauthorized)

				return
			}
			groups, ok := authentication.GetGroups(ctx)
			if !ok {
				groups = []string{}
			}
			a, ok := authorizers[tenant]
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant", http.StatusUnauthorized)

				return
			}

			token, ok := authentication.GetAccessToken(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding access token", http.StatusUnauthorized)

				return
			}

			tenantID, ok := authentication.GetTenantID(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant id", http.StatusUnauthorized)

				return
			}

			selectorsInfo, ok := GetSelectorsInfo(r.Context())
			if !ok {
				selectorsInfo = emptySelectorsInfo
			}

			metadataOnly := isMetadataRequest(r.URL.Path)

			extraAttributes := &rbac.ExtraAttributes{
				Selectors:         selectorsInfo.Selectors,
				WildcardSelectors: selectorsInfo.HasWildcard,
				MetadataOnly:      metadataOnly,
			}

			statusCode, ok, data := a.Authorize(subject, groups, permission, resource, tenant, tenantID, token, extraAttributes)
			if !ok {
				// Send 403 http.StatusForbidden
				w.WriteHeader(statusCode)

				return
			}
			next.ServeHTTP(w, r.WithContext(WithData(ctx, data)))
		})
	}
}
