package observatorium

import data.roleBindings
import data.roles

default allow := false

# Main allow rule with path-based authorization
allow if {
  some role_binding in roleBindings
  matched_role_binding(role_binding.subjects, input.subject, input.groups)
  some role_name in role_binding.roles
  some data_role in roles
  role_name == data_role.name
  input.resource in data_role.resources
  input.permission in data_role.permissions
  input.tenant in data_role.tenants
  # Check if the request path matches allowed paths for this role
  path_allowed(data_role.paths, input.path)
}

# Helper function to check if a path is allowed
path_allowed(allowed_paths, request_path) if {
  some allowed_path in allowed_paths
  # Direct match
  allowed_path == request_path
}

path_allowed(allowed_paths, request_path) if {
  some allowed_path in allowed_paths
  # Wildcard match - if allowed_path ends with /*
  endswith(allowed_path, "/*")
  prefix := substring(allowed_path, 0, count(allowed_path) - 2)
  startswith(request_path, prefix)
}

# User matching
matched_role_binding(subjects, input_req_subject, _) if {
	some subject in subjects
	subject.kind == "user"
	subject.name == input_req_subject
}

# Group matching
matched_role_binding(subjects, _, input_req_groups) if {
	some group in subjects
	some input_req_group in input_req_groups
	group.kind == "group"
	group.name == input_req_group
}

# Debug function to show which paths are being evaluated
debug_paths[data_role.name] = data_role.paths if {
  some data_role in roles
  count(data_role.paths) > 0
}