package rbac

import (
	"fmt"
	"io"
	"net/http"

	"github.com/ghodss/yaml"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
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

// Authorizer can authorize a subject's permission for a tenant's resource.
type Authorizer interface {
	// Authorize answers the question: can subject S in groups G perform permission P on resource R for Tenant T?
	Authorize(subject string, groups []string, permission Permission, resource, tenant, tenantID, token string) (int, bool, string)
}

// tenant represents the read and write permissions of many subjects on a single tenant.
type tenant struct {
	read  map[Subject]struct{}
	write map[Subject]struct{}
}

// tenants is a map of tenant names to read and write permissions for subjects.
type tenants map[string]tenant

// resources is a map of resource names to the permissions on tenants.
type resources struct {
	tenants map[string]tenants
	logger  log.Logger
}

// Authorize implements the Authorizer interface.
func (rs resources) Authorize(subject string, groups []string, permission Permission, resource, tenant,
	tenantID, token string) (int, bool, string) {
	ts, ok := rs.tenants[resource]
	if !ok {
		level.Debug(rs.logger).Log("msg",
			fmt.Sprintf("authorization: resource %q unknown; valid resources are %v", resource, rs))
		return http.StatusForbidden, false, ""
	}

	t, ok := ts[tenant]
	if !ok {
		level.Debug(rs.logger).Log("msg",
			fmt.Sprintf("authorization: tenant %q unknown (%d valid tenants for resource %q)",
				tenant, len(ts), resource))

		return http.StatusForbidden, false, ""
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
		return http.StatusOK, ok, ""
	}

	// Now check the user's groups.
	for _, group := range groups {
		if _, ok := pmap[Subject{Name: group, Kind: Group}]; ok {
			return http.StatusOK, ok, ""
		}
	}

	level.Debug(rs.logger).Log("msg",
		fmt.Sprintf("authorization: %q unknown; groups %v unknown",
			subject, groups))

	return http.StatusForbidden, false, ""
}

// NewAuthorizer creates a new Authorizer.
//
//nolint:gocognit
func NewAuthorizer(roles []Role, roleBindings []RoleBinding, logger log.Logger) Authorizer {
	rs := make(map[string]Role)
	for _, role := range roles {
		rs[role.Name] = role
	}

	resources := resources{
		tenants: make(map[string]tenants),
		logger:  logger,
	}

	for _, rb := range roleBindings {
		for _, roleName := range rb.Roles {
			role, ok := rs[roleName]
			if !ok {
				level.Warn(logger).Log("msg", fmt.Sprintf("Unexpected role %q", roleName))
				continue
			}

			for _, resourceName := range role.Resources {
				if _, ok := resources.tenants[resourceName]; !ok {
					resources.tenants[resourceName] = make(tenants)
				}

				t := resources.tenants[resourceName]

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
							default:
								level.Warn(logger).Log("msg",
									fmt.Sprintf("Ignoring unexpected role permission %q for subject %q in tenant %q in role %q", p,
										s, tenantName, roleName))
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
func Parse(r io.Reader, logger log.Logger) (Authorizer, error) {
	rbac := struct {
		Roles        []Role        `json:"roles"`
		RoleBindings []RoleBinding `json:"roleBindings"`
	}{}

	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not read RBAC data: %w", err)
	}

	if err := yaml.Unmarshal(raw, &rbac); err != nil {
		return nil, fmt.Errorf("could not parse RBAC data: %w", err)
	}

	return NewAuthorizer(rbac.Roles, rbac.RoleBindings, logger), nil
}
