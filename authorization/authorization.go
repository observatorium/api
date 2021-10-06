package authorization

import (
	"fmt"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

const (
	// Write gives access to write data to a tenant.
	Write Permission = "write"
	// Read gives access to read data from a tenant.
	Read Permission = "read"
)

// Permission is an Observatorium RBAC permission.
type Permission string

// Provider interface should be implemented to onboard a new authorization
// provider.
type Provider interface {
	// Authorize answers the question: can subject S in groups G perform permission P on resource R for Tenant T?
	Authorize(subject string, groups []string, permission Permission, resource, tenant, tenantID, token string) (int, bool, string)
}

//nolint:gochecknoglobals
// providerFactories map is used for the providers' self-registration.
var providerFactories map[string]ProviderFactory

//nolint:gochecknoglobals
// providersMtx is used to protect the providerFactories.
var providersMtx sync.RWMutex

//nolint:gochecknoinits
func init() {
	providerFactories = make(map[string]ProviderFactory)
}

// onboardNewProvider is used by the providers to register themselves.
func onboardNewProvider(providerType string, factory ProviderFactory) {
	providersMtx.Lock()
	defer providersMtx.Unlock()

	providerFactories[providerType] = factory
}

// Each authorizer factory must meet this factory signature.
type ProviderFactory func(config map[string]interface{}, tenant string, logger log.Logger) (Provider, error)

// InitializeProvider initializes an authorization provider.
func InitializeProvider(config map[string]interface{},
	tenant string, authType string, logger log.Logger) (Provider, error) {
	if config == nil {
		return nil, fmt.Errorf("failed to initialize provider, config is required")
	}

	providerFactory, err := getProviderFactory(authType)
	if err != nil {
		return nil, err
	}

	provider, err := providerFactory(config, tenant, logger)
	if err != nil {
		return nil, err
	}

	level.Debug(logger).Log("msg", "successfully initialized authorizer", "tenant", tenant, "authorizer", authType)

	return provider, nil
}

func getProviderFactory(authorizerType string) (ProviderFactory, error) {
	providersMtx.RLock()
	defer providersMtx.RUnlock()

	providerFactory, ok := providerFactories[authorizerType]
	if !ok {
		return nil, fmt.Errorf("authorizer of type: %s is not supported", authorizerType)
	}

	return providerFactory, nil
}
