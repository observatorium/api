package authorization

import (
	"fmt"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/logger"
)

type DummyAuthorizerConfig struct {
	Name string `json:"name"`
}

type DummyAuthorizer struct {
	config DummyAuthorizerConfig
}

func (a DummyAuthorizer) Authorize(subject string, groups []string, permission Permission,
	resource, tenant, tenantID, token string) (int, bool, string) {
	return 200, true, ""
}

func newDummyAuthorizer(c map[string]interface{}, tenant string, logger log.Logger) (Provider, error) {
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
	tenantName := "test-tenant"
	dummyAuthorizerConfig := map[string]interface{}{"name": "test"}
	l := logger.NewLogger("info", logger.LogFormatLogfmt, "")

	onboardNewProvider(dummyAuthorizerType, newDummyAuthorizer)

	t.Run("Getting an authorization factory", func(t *testing.T) {
		providerFactory, err := getProviderFactory(dummyAuthorizerType)
		if providerFactory == nil {
			t.Fatal("dummy provider factory should not be nil")
		}

		if err != nil {
			t.Fatal("getting the dummy's provider factory should not fail")
		}

		unregisteredFactory, err := getProviderFactory("unregistered-authenticator")
		if unregisteredFactory != nil || err == nil {
			t.Fatal("getting unregistered factory should fail and return a nil")
		}
	})

	t.Run("initialize dummy authorizer", func(t *testing.T) {
		initializedAuthorizer, err := InitializeProvider(dummyAuthorizerConfig, tenantName, dummyAuthorizerType, l)
		if initializedAuthorizer == nil || err != nil {
			t.Fatal("initializing an existing authorization's provider should return the initialized authorizer with no error")
		}
	})

	t.Run("initialize dummy authorizer with nil config", func(t *testing.T) {
		initializedAuthorizer, err := InitializeProvider(nil, tenantName, dummyAuthorizerType, l)
		if initializedAuthorizer != nil || err == nil {
			t.Fatal("initializing an authorization's provider with an empty config should fail and return an error")
		}
	})

	t.Run("initialize a non-exist authorizer", func(t *testing.T) {
		initializedAuthorizer, err := InitializeProvider(dummyAuthorizerConfig, tenantName, "non-exist-authorizer-type", l)
		if initializedAuthorizer != nil || err == nil {
			t.Fatal("initializing a non-existing authorization's provider should fail and return an error")
		}
	})
}
