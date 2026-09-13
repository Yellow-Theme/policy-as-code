package iam.wildcard

import rego.v1

# Synthetic IAM statements. Deny Action or Resource of "*".
# A passing statement is not a claim that a criterion is met.

is_wildcard(value) if {
	value == "*"
}

is_wildcard(value) if {
	some item in value
	item == "*"
}

deny contains msg if {
	some stmt in input.statements
	is_wildcard(object.get(stmt, "Action", ""))
	msg := sprintf("CC6.3 access: statement %q must not set Action to *", [object.get(stmt, "Sid", "(no sid)")])
}

deny contains msg if {
	some stmt in input.statements
	is_wildcard(object.get(stmt, "Resource", ""))
	msg := sprintf("CC6.3 access: statement %q must not set Resource to *", [object.get(stmt, "Sid", "(no sid)")])
}
