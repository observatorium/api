package providers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/ghodss/yaml"
	"github.com/mitchellh/mapstructure"
	"github.com/observatorium/api/authorization"
)

//nolint:gochecknoinits
func init() {
	authorizersFactories["rbac"] = newRBACAuthorizer
}

type SubjectKind string

type tenant struct {
	read  map[Subject]struct{}
	write map[Subject]struct{}
}

// tenants is a map of tenant names to read and write permissions for subjects.
type tenants map[string]tenant

// resources is a map of resource names to the permissions on tenants.
type resources map[string]tenants

type RBACAuthorizerConfig struct {
	RBACFilePath string `json:"rbacFilePath"`
}

type RBACAuthorizer struct {
	// resources is a map of resource names to the permissions on tenants.
	resources resources
}

type Role struct {
	Name        string                     `json:"name"`
	Resources   []string                   `json:"resources"`
	Tenants     []string                   `json:"tenants"`
	Permissions []authorization.Permission `json:"permissions"`
}

type Subject struct {
	Name string      `json:"name"`
	Kind SubjectKind `json:"kind"`
}

type RoleBinding struct {
	Name     string    `json:"name"`
	Subjects []Subject `json:"subjects"`
	Roles    []string  `json:"roles"`
}

const (
	// User represents a subject that is a user.
	User SubjectKind = "user"
	// Group represents a subject that is a group.
	Group SubjectKind = "group"
)

func rbacAuthorizer(roles []Role, roleBindings []RoleBinding) authorization.Authorizer {
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

	return RBACAuthorizer{
		resources: resources,
	}
}

//nolint:gocognit
func newRBACAuthorizer(c map[string]interface{}, baseAuthorizer *AuthorizationProviderBase) (authorization.Authorizer, error) {
	var config RBACAuthorizerConfig

	rbac := struct {
		Roles        []Role        `json:"roles"`
		RoleBindings []RoleBinding `json:"roleBindings"`
	}{}

	if err := mapstructure.Decode(c, &config); err != nil {
		return nil, err
	}

	f, err := os.Open(config.RBACFilePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read RBAC configuration file from path %q: %v", config.RBACFilePath, err)
	}
	defer f.Close()

	raw, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read RBAC data: %w", err)
	}

	if err := yaml.Unmarshal(raw, &rbac); err != nil {
		return nil, fmt.Errorf("could not parse RBAC data: %w", err)
	}

	return rbacAuthorizer(rbac.Roles, rbac.RoleBindings), nil
}

func (a RBACAuthorizer) Authorize(subject string, groups []string, permission authorization.Permission,
	resource, tenant, tenantID, token string) (int, bool, string) {
	ts, ok := a.resources[resource]

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
