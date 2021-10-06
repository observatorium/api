package providers

import (
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/observatorium/api/authorization"
)

//nolint:gochecknoglobals
// authorizersFactories map is used by the authorization providers
// to self-register themselves.
var authorizersFactories map[string]AuthorizerFactory

//nolint:gochecknoinits
func init() {
	// This will be first initialize, so that the authorizers can register themselves.
	authorizersFactories = make(map[string]AuthorizerFactory)
}

// Each authorizer factory must meet this factory signature.
type AuthorizerFactory func(c map[string]interface{}, authorizationProviderBase *AuthorizationProviderBase) (authorization.Authorizer, error)

// AuthorizationProviderBase holds the base information of an authorizer.
type AuthorizationProviderBase struct {
	Tenant string
	Type   string
	Logger log.Logger
}

// InitializeTenantAuthorizer initializes an authorization provider and register the created
// authorization middleware and handlers.
func InitializeTenantAuthorizer(config map[string]interface{},
	baseAuthorizer *AuthorizationProviderBase) (authorization.Authorizer, error) {
	authorizerFactory, err := getAuthorizerFactory(baseAuthorizer.Type)
	if err != nil {
		return nil, err
	}

	authorizer, err := authorizerFactory(config, baseAuthorizer)
	if err != nil {
		return nil, err
	}

	return authorizer, nil
}

func getAuthorizerFactory(authorizerType string) (AuthorizerFactory, error) {
	factory, ok := authorizersFactories[authorizerType]
	if !ok {
		return nil, fmt.Errorf("authorizer of type: %s is not supported", authorizerType)
	}

	return factory, nil
}
