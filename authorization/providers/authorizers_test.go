package providers

import (
	"fmt"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/authorization"
	"github.com/observatorium/api/logger"
	"github.com/stretchr/testify/require"
)

type DummyAuthorizerConfig struct {
	Name string `json:"name"`
}

type DummyAuthorizer struct {
	config DummyAuthorizerConfig
}

func (a DummyAuthorizer) Authorize(subject string, groups []string, permission authorization.Permission,
	resource, tenant, tenantID, token string) (int, bool, string) {
	return 200, true, ""
}

func newDummyAuthorizer(c map[string]interface{}, authorizationProviderBase *AuthorizationProviderBase) (authorization.Authorizer, error) {
	var config DummyAuthorizerConfig

	err := mapstructure.Decode(c, &config)
	if err != nil {
		return nil, err
	}

	if config.Name == "" {
		return nil, fmt.Errorf("Name must be passed")
	}

	return DummyAuthorizer{
		config: config,
	}, nil
}
func TestAuthorizers(t *testing.T) {
	dummyAuthorizerType := "dummy-authorizer"
	dummyAuthorizerConfig := map[string]interface{}{"name": "test"}
	l := logger.NewLogger("info", logger.LogFormatLogfmt, "")

	authorizersFactories[dummyAuthorizerType] = newDummyAuthorizer

	baseAuthorizer := &AuthorizationProviderBase{
		Tenant: "test-tenant",
		Logger: l,
		Type:   dummyAuthorizerType,
	}

	t.Run("Getting an authorization factory", func(t *testing.T) {
		_, err := getAuthorizerFactory(baseAuthorizer.Type)
		require.NoError(t, err, "authorizer factory should be there")

		_, err = getAuthorizerFactory("unregistered-authenticator")
		require.Error(t, err, "getting an authenticator factory of unregistered authenticator should fail")
	})

	t.Run("initialize dummy authorizer", func(t *testing.T) {
		initializedAuthorizer, err := InitializeTenantAuthorizer(dummyAuthorizerConfig, baseAuthorizer)
		require.NotNil(t, initializedAuthorizer, "initialized authorizer should not be nil")
		require.NoError(t, err, "initializing a valid authorizer should not throw an error")
	})

	t.Run("initialize dummy authorizer with nil config", func(t *testing.T) {
		initializedAuthorizer, err := InitializeTenantAuthorizer(nil, baseAuthorizer)
		require.Error(t, err, "initializing a dummy authorizer with missing config should throw an error")
		require.Nil(t, initializedAuthorizer, "failed authorizer initialization should return a nil authorizer")
	})

	t.Run("initialize a non-exist authorizer", func(t *testing.T) {
		baseAuthorizer := &AuthorizationProviderBase{
			Tenant: "dummy-tenant",
			Logger: l,
			Type:   "non-exist-authorizer-type",
		}
		_, err := InitializeTenantAuthorizer(dummyAuthorizerConfig, baseAuthorizer)
		require.Error(t, err, "initializing a non-exist authorizer should throw an error")
	})
}
