package authorization

import (
	"context"
	"fmt"
	"net/http"

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

	// authorizationNamespacesKey is the key that holds the LogQL query namespaces in a request context.
	authorizationNamespacesKey contextKey = "logqlQueryNamespaces"
)

type NamespaceInfo struct {
	Namespaces  []string
	HasWildcard bool
}

var (
	emptyNamespaceInfo = &NamespaceInfo{
		Namespaces: []string{},
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

// GetNamespaceInfo extracts the query namespaces from the provided context.
func GetNamespaceInfo(ctx context.Context) (*NamespaceInfo, bool) {
	value := ctx.Value(authorizationNamespacesKey)
	namespaces, ok := value.(*NamespaceInfo)

	return namespaces, ok
}

// WithNamespaceInfo extends the provided context with the query namespaces.
func WithNamespaceInfo(ctx context.Context, info *NamespaceInfo) context.Context {
	return context.WithValue(ctx, authorizationNamespacesKey, info)
}

// WithLogsQueryNamespaceExtractor returns a middleware that, when enabled, tries to extract
// the list of namespaces it queries from a LogQL expression.
func WithLogsQueryNamespaceExtractor(namespaceLabels []string) func(http.Handler) http.Handler {
	enabled := len(namespaceLabels) > 0

	namespaceLabelMap := make(map[string]bool, len(namespaceLabels))
	for _, l := range namespaceLabels {
		namespaceLabelMap[l] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)

				return
			}

			namespaceInfo, err := extractQueryNamespaces(namespaceLabelMap, r.URL.Query())
			if err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("error extracting query namespaces: %s", err), http.StatusInternalServerError)

				return
			}

			next.ServeHTTP(w, r.WithContext(WithNamespaceInfo(r.Context(), namespaceInfo)))
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

			namespaceInfo, ok := GetNamespaceInfo(r.Context())
			if !ok {
				namespaceInfo = emptyNamespaceInfo
			}

			metadataOnly := isMetadataRequest(r.URL.Path)

			extraAttributes := &rbac.ExtraAttributes{
				Logs: &rbac.LogsExtraAttributes{
					Namespaces:         namespaceInfo.Namespaces,
					WildcardNamespaces: namespaceInfo.HasWildcard,
					MetadataOnly:       metadataOnly,
				},
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
