package rbac

import "testing"

// nolint:funlen,scopelint
func TestNewAuthorizer(t *testing.T) {
	type io struct {
		subject    string
		groups     []string
		permission Permission
		resource   string
		tenant     string
		output     bool
	}

	for _, tc := range []struct {
		name         string
		roles        []Role
		roleBindings []RoleBinding
		ios          []io
	}{
		{
			name: "empty",
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "only roles",
			roles: []Role{
				{
					Name:        "a-write",
					Resources:   []string{"foo"},
					Tenants:     []string{"a"},
					Permissions: []Permission{"write"},
				},
				{
					Name:        "b-write",
					Resources:   []string{"foo"},
					Tenants:     []string{"b"},
					Permissions: []Permission{"write"},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "only merged roles",
			roles: []Role{
				{
					Name:        "a-b-write",
					Resources:   []string{"foo"},
					Tenants:     []string{"a", "b"},
					Permissions: []Permission{"write"},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "only role bindings",
			roleBindings: []RoleBinding{
				{
					Name:     "erika-a",
					Roles:    []string{"a-write"},
					Subjects: []Subject{{Name: "erika", Kind: User}},
				},
				{
					Name:     "max-a",
					Roles:    []string{"b-write"},
					Subjects: []Subject{{Name: "max", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "only merged role bindings",
			roleBindings: []RoleBinding{
				{
					Name:     "a-b",
					Roles:    []string{"a-b-write"},
					Subjects: []Subject{{Name: "erika", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "erika write foo for a",
			roles: []Role{
				{
					Name:        "a-write",
					Resources:   []string{"foo"},
					Tenants:     []string{"a"},
					Permissions: []Permission{"write"},
				},
				{
					Name:        "b-write",
					Resources:   []string{"foo"},
					Tenants:     []string{"b"},
					Permissions: []Permission{"write"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "erika-a",
					Roles:    []string{"a-write"},
					Subjects: []Subject{{Name: "erika", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "erika write foo and bar for a",
			roles: []Role{
				{
					Name:        "a-write",
					Resources:   []string{"foo", "bar"},
					Tenants:     []string{"a"},
					Permissions: []Permission{"write"},
				},
				{
					Name:        "b-write",
					Resources:   []string{"foo"},
					Tenants:     []string{"b"},
					Permissions: []Permission{"write"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "erika-a",
					Roles:    []string{"a-write"},
					Subjects: []Subject{{Name: "erika", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "erika read-write foo and bar for a",
			roles: []Role{
				{
					Name:        "rw",
					Resources:   []string{"foo", "bar"},
					Tenants:     []string{"a"},
					Permissions: []Permission{"read", "write"},
				},
				{
					Name:        "b-write",
					Resources:   []string{"foo"},
					Tenants:     []string{"b"},
					Permissions: []Permission{"write"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "erika-a",
					Roles:    []string{"rw"},
					Subjects: []Subject{{Name: "erika", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "bar",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "both write foo for a",
			roles: []Role{
				{
					Name:        "writer",
					Resources:   []string{"foo"},
					Tenants:     []string{"a"},
					Permissions: []Permission{"write"},
				},
				{
					Name:        "reader",
					Resources:   []string{"foo"},
					Tenants:     []string{"a", "b"},
					Permissions: []Permission{"reader"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "a",
					Roles:    []string{"writer"},
					Subjects: []Subject{{Name: "erika", Kind: User}, {Name: "max", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "both write for a and b",
			roles: []Role{
				{
					Name:        "writer",
					Resources:   []string{"foo"},
					Tenants:     []string{"a", "b"},
					Permissions: []Permission{"write"},
				},
				{
					Name:        "reader",
					Resources:   []string{"foo"},
					Tenants:     []string{"a", "b"},
					Permissions: []Permission{"reader"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "a",
					Roles:    []string{"writer"},
					Subjects: []Subject{{Name: "erika", Kind: User}, {Name: "max", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "bar",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
			},
		},
		{
			name: "both read foo for b",
			roles: []Role{
				{
					Name:        "writer",
					Resources:   []string{"foo"},
					Tenants:     []string{"a", "b"},
					Permissions: []Permission{"write"},
				},
				{
					Name:        "reader",
					Resources:   []string{"foo"},
					Tenants:     []string{"b"},
					Permissions: []Permission{"read"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "b",
					Roles:    []string{"reader"},
					Subjects: []Subject{{Name: "erika", Kind: User}, {Name: "max", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "max",
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "max",
					permission: Read,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "both read-write foo for a and b",
			roles: []Role{
				{
					Name:        "writer",
					Resources:   []string{"foo"},
					Tenants:     []string{"a", "b"},
					Permissions: []Permission{"write"},
				},
				{
					Name:        "reader",
					Resources:   []string{"foo"},
					Tenants:     []string{"b", "a"},
					Permissions: []Permission{"read"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "a-b",
					Roles:    []string{"reader", "writer"},
					Subjects: []Subject{{Name: "erika", Kind: User}, {Name: "max", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "max",
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "both read-write merged",
			roles: []Role{
				{
					Name:        "rw",
					Resources:   []string{"foo"},
					Tenants:     []string{"a", "b"},
					Permissions: []Permission{"read", "write"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "a-b",
					Roles:    []string{"rw"},
					Subjects: []Subject{{Name: "erika", Kind: User}, {Name: "max", Kind: User}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "max",
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     true,
				},
				{
					subject:    "max",
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "group mustermann read for a",
			roles: []Role{
				{
					Name:        "a-read",
					Resources:   []string{"foo"},
					Tenants:     []string{"a"},
					Permissions: []Permission{"read"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "mustermann-a",
					Roles:    []string{"a-read"},
					Subjects: []Subject{{Name: "mustermann", Kind: Group}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					groups:     []string{"mustermann"},
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					groups:     []string{"mustermann"},
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					groups:     []string{"mustermann"},
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
			},
		},
		{
			name: "group erika read for a",
			roles: []Role{
				{
					Name:        "a-read",
					Resources:   []string{"foo"},
					Tenants:     []string{"a"},
					Permissions: []Permission{"read"},
				},
			},
			roleBindings: []RoleBinding{
				{
					Name:     "erika-a",
					Roles:    []string{"a-read"},
					Subjects: []Subject{{Name: "erika", Kind: Group}},
				},
			},
			ios: []io{
				{
					subject:    "erika",
					groups:     []string{"erika", "mustermann"},
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     true,
				},
				{
					subject:    "erika",
					groups:     []string{"erika", "mustermann"},
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "erika",
					groups:     []string{"erika", "mustermann"},
					permission: Read,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Read,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Write,
					resource:   "foo",
					tenant:     "a",
					output:     false,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Write,
					resource:   "foo",
					tenant:     "b",
					output:     false,
				},
				{
					subject:    "max",
					groups:     []string{"mustermann", "other"},
					permission: Write,
					resource:   "bar",
					tenant:     "b",
					output:     false,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAuthorizer(tc.roles, tc.roleBindings)
			for i := range tc.ios {
				if a.Authorize(tc.ios[i].subject, tc.ios[i].groups, tc.ios[i].permission, tc.ios[i].resource, tc.ios[i].tenant) != tc.ios[i].output {
					t.Errorf("test case %d: expected %t; got %t", i, tc.ios[i].output, !tc.ios[i].output)
				}
			}
		})
	}
}
