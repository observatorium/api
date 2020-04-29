package rbac

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v2"
)

// Permission is an Observatorium RBAC permission.
type Permission string

const (
	// Write gives access to write data to a tenant.
	Write Permission = "write"
	// Read gives access to read data from a tenant.
	Read Permission = "read"
)

// Role describes a set of permissions to interact with a tenant.
type Role struct {
	Name        string       `json:"name" yaml:"name"`
	Resources   []string     `json:"resources" yaml:"resources"`
	Tenants     []string     `json:"tenants" yaml:"tenants"`
	Permissions []Permission `json:"permissions" yaml:"permissions"`
}

// RoleBinding binds a set of roles to a set of subjects.
type RoleBinding struct {
	Name     string   `json:"name" yaml:"name"`
	Subjects []string `json:"subjects" yaml:"subjects"`
	Roles    []string `json:"roles" yaml:"roles"`
}

// TODO: move interface definition.
// Authorizer can authorize a subject's permission for a tentant's resource.
type Authorizer interface {
	// Authorize answers the question: can subject S perform permission P on resource R for Tenant T?
	Authorize(subject string, permission Permission, resource, tenant string) bool
}

// tenant represents the read and write permissions of many subjects on a single tenant.
type tenant struct {
	read  map[string]struct{}
	write map[string]struct{}
}

// tenants is a map of tenant names to read and write permissions for subjects.
type tenants map[string]tenant

// resources is a map of resource names to the permissions on tenants.
type resources map[string]tenants

// Authorize implements the Authorizer interface.
func (rs resources) Authorize(subject string, permission Permission, resource, tenant string) bool {
	ts, ok := rs[resource]
	if !ok {
		return false
	}

	t, ok := ts[tenant]
	if !ok {
		return false
	}

	switch permission {
	case Read:
		_, ok := t.read[subject]
		return ok
	case Write:
		_, ok := t.write[subject]
		return ok
	}

	return false
}

// NewAuthorizer creates a new Authorizer.
func NewAuthorzer(roles []Role, roleBindings []RoleBinding) Authorizer {
	rs := make(map[string]Role)
	for _, role := range roles {
		rs[role.Name] = role
	}

	resources := make(resources)

	for _, rb := range roleBindings {
		for _, roleName := range rb.Roles {
			role, ok := rs[roleName]
			if !ok {
				continue
			}

			for _, resourceName := range role.Resources {
				if _, ok := resources[resourceName]; !ok {
					resources[resourceName] = make(tenants)
				}

				t := resources[resourceName]

				for _, tenantName := range role.Tenants {
					if _, ok := t[tenantName]; !ok {
						t[tenantName] = tenant{
							read:  make(map[string]struct{}),
							write: make(map[string]struct{}),
						}
					}

					for _, s := range rb.Subjects {
						for _, p := range role.Permissions {
							switch p {
							case Read:
								t[tenantName].read[s] = struct{}{}
							case Write:
								t[tenantName].write[s] = struct{}{}
							}
						}
					}
				}
			}
		}
	}

	return resources
}

// Parse parses RBAC data from a reader and creates a new Authorizer.
func Parse(r io.Reader) (Authorizer, error) {
	rbac := struct {
		Roles        []Role        `json:"roles" yaml:"roles"`
		RoleBindings []RoleBinding `json:"roleBindings" yaml:"roleBindings"`
	}{}

	if err := yaml.NewDecoder(r).Decode(&rbac); err != nil {
		return nil, fmt.Errorf("could not parse RBAC data: %w", err)
	}

	return NewAuthorzer(rbac.Roles, rbac.RoleBindings), nil
}
