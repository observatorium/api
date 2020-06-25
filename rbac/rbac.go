package rbac

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/ghodss/yaml"
)

// Permission is an Observatorium RBAC permission.
type Permission string

// SubjectKind is a kind of Observatorium RBAC subject.
type SubjectKind string

const (
	// Write gives access to write data to a tenant.
	Write Permission = "write"
	// Read gives access to read data from a tenant.
	Read Permission = "read"

	// User represents a subject that is a user.
	User SubjectKind = "user"
	// Group represents a subject that is a group.
	Group SubjectKind = "group"
)

// Role describes a set of permissions to interact with a tenant.
type Role struct {
	Name        string       `json:"name"`
	Resources   []string     `json:"resources"`
	Tenants     []string     `json:"tenants"`
	Permissions []Permission `json:"permissions"`
}

// Subject represents a subject that has been bound to a role.
type Subject struct {
	Name string      `json:"name"`
	Kind SubjectKind `json:"kind"`
}

// RoleBinding binds a set of roles to a set of subjects.
type RoleBinding struct {
	Name     string    `json:"name"`
	Subjects []Subject `json:"subjects"`
	Roles    []string  `json:"roles"`
}

// TODO: move interface definition.
// Authorizer can authorize a subject's permission for a tentant's resource.
type Authorizer interface {
	// Authorize answers the question: can subject S in groups G perform permission P on resource R for Tenant T?
	Authorize(subject string, groups []string, permission Permission, resource, tenant string) bool
}

// tenant represents the read and write permissions of many subjects on a single tenant.
type tenant struct {
	read  map[Subject]struct{}
	write map[Subject]struct{}
}

// tenants is a map of tenant names to read and write permissions for subjects.
type tenants map[string]tenant

// resources is a map of resource names to the permissions on tenants.
type resources map[string]tenants

// Authorize implements the Authorizer interface.
func (rs resources) Authorize(subject string, groups []string, permission Permission, resource, tenant string) bool {
	ts, ok := rs[resource]
	if !ok {
		return false
	}

	t, ok := ts[tenant]
	if !ok {
		return false
	}

	var pmap map[Subject]struct{}
	switch permission {
	case Read:
		pmap = t.read
	case Write:
		pmap = t.write
	}

	// First check the user directly
	if _, ok := pmap[Subject{Name: subject, Kind: User}]; ok {
		return ok
	}

	// Now check the user's groups.
	for _, group := range groups {
		if _, ok := pmap[Subject{Name: group, Kind: Group}]; ok {
			return ok
		}
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
							read:  make(map[Subject]struct{}),
							write: make(map[Subject]struct{}),
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
		Roles        []Role        `json:"roles"`
		RoleBindings []RoleBinding `json:"roleBindings"`
	}{}

	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not read RBAC data: %w", err)
	}
	if err := yaml.Unmarshal(raw, &rbac); err != nil {
		return nil, fmt.Errorf("could not parse RBAC data: %w", err)
	}

	return NewAuthorzer(rbac.Roles, rbac.RoleBindings), nil
}
