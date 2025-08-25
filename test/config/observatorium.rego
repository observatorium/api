package observatorium

import data.roleBindings
import data.roles

default allow := false

allow if {
  some role_binding in roleBindings
  matched_role_binding(role_binding.subjects, input.subject, input.groups)
  some role_name in role_binding.roles
  some data_role in roles
  role_name == data_role.name
  input.resource in data_role.resources
  input.permission in data_role.permissions
  input.tenant in data_role.tenants
}

matched_role_binding(subjects, input_req_subject, _) if {
	some subject in subjects
	subject.kind == "user"
	subject.name == input_req_subject
}

matched_role_binding(subjects, _, input_req_groups) if {
	some group in subjects
	some input_req_group in input_req_groups
	group.kind == "group"
	group.name == input_req_group
}
