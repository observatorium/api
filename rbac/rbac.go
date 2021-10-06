package rbac

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/ghodss/yaml"
	"github.com/observatorium/api/authorization"
)

// SubjectKind is a kind of Observatorium RBAC subject.
type SubjectKind string

const (
	// User represents a subject that is a user.
	User SubjectKind = "user"
	// Group represents a subject that is a group.
	Group SubjectKind = "group"
)

// Role describes a set of permissions to interact with a tenant.
type Role struct {
	Name        string                     `json:"name"`
	Resources   []string                   `json:"resources"`
	Tenants     []string                   `json:"tenants"`
	Permissions []authorization.Permission `json:"permissions"`
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
func (rs resources) Authorize(subject string, groups []string, permission authorization.Permission, resource, tenant,
	tenantID, token string) (int, bool, string) {
	ts, ok := rs[resource]
	if !ok {
		return http.StatusForbidden, false, ""
	}

	t, ok := ts[tenant]
	if !ok {
		return http.StatusForbidden, false, ""
	}

	var pmap map[Subject]struct{}

	switch permission {
	case authorization.Read:
		pmap = t.read
	case authorization.Write:
		pmap = t.write
	}

	// First check the user directly
	if _, ok := pmap[Subject{Name: subject, Kind: User}]; ok {
		return http.StatusOK, ok, ""
	}

	// Now check the user's groups.
	for _, group := range groups {
		if _, ok := pmap[Subject{Name: group, Kind: Group}]; ok {
			return http.StatusOK, ok, ""
		}
	}

	return http.StatusForbidden, false, ""
}

//nolint:gocognit
// NewAuthorizer creates a new Authorizer.
func NewAuthorizer(roles []Role, roleBindings []RoleBinding) authorization.Authorizer {
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
							case authorization.Read:
								t[tenantName].read[s] = struct{}{}
							case authorization.Write:
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
func Parse(r io.Reader) (authorization.Authorizer, error) {
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

	return NewAuthorizer(rbac.Roles, rbac.RoleBindings), nil
}
