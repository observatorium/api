package authorization

const (
	// Write gives access to write data to a tenant.
	Write Permission = "write"
	// Read gives access to read data from a tenant.
	Read Permission = "read"
)

// Permission is an Observatorium RBAC permission.
type Permission string

// Authorizer interface should be implemented to onboard a new authorization
// provider.
type Authorizer interface {
	// Authorize answers the question: can subject S in groups G perform permission P on resource R for Tenant T?
	Authorize(subject string, groups []string, permission Permission, resource, tenant, tenantID, token string) (int, bool, string)
}
