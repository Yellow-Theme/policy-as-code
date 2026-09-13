package iam.wildcard

import rego.v1

scoped := {
	"statements": [{
		"Sid": "ReadSyntheticObject",
		"Action": "s3:GetObject",
		"Resource": "arn:aws:s3:::synthetic-object/*",
	}],
}

test_scoped_passes if {
	count(deny) == 0 with input as scoped
}

test_empty_passes if {
	count(deny) == 0 with input as {"statements": []}
}

test_action_star_fails if {
	msgs := deny with input as {"statements": [{"Sid": "TooWide", "Action": "*", "Resource": "arn:aws:s3:::synthetic-object/*"}]}
	some msg in msgs
	contains(msg, "CC6.3 access")
	contains(msg, "Action")
}

test_action_list_star_fails if {
	msgs := deny with input as {"statements": [{"Sid": "TooWide", "Action": ["s3:GetObject", "*"], "Resource": "arn:aws:s3:::synthetic-object/*"}]}
	some msg in msgs
	contains(msg, "CC6.3 access")
	contains(msg, "Action")
}

test_resource_star_fails if {
	msgs := deny with input as {"statements": [{"Sid": "TooWide", "Action": "s3:GetObject", "Resource": "*"}]}
	some msg in msgs
	contains(msg, "CC6.3 access")
	contains(msg, "Resource")
}

test_resource_list_star_fails if {
	msgs := deny with input as {"statements": [{"Sid": "TooWide", "Action": "s3:GetObject", "Resource": ["arn:aws:s3:::synthetic-object/*", "*"]}]}
	some msg in msgs
	contains(msg, "CC6.3 access")
	contains(msg, "Resource")
}
