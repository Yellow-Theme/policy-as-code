package change.exception

import rego.v1

inside := {"change": {"outside_window": false}, "as_of": "2026-09-13"}

valid := {
	"change": {"outside_window": true},
	"as_of": "2026-09-13",
	"exception": {"reason": "synthetic window miss", "expires": "2026-12-31"},
}

test_inside_window_passes if {
	count(deny) == 0 with input as inside
}

test_valid_exception_passes if {
	count(deny) == 0 with input as valid
}

test_missing_reason_fails if {
	msgs := deny with input as {
		"change": {"outside_window": true},
		"as_of": "2026-09-13",
		"exception": {"expires": "2026-12-31"},
	}
	some msg in msgs
	contains(msg, "CC8.1 exception")
	contains(msg, "missing reason")
}

test_expired_fails if {
	msgs := deny with input as {
		"change": {"outside_window": true},
		"as_of": "2026-09-13",
		"exception": {"reason": "synthetic window miss", "expires": "2026-01-01"},
	}
	some msg in msgs
	contains(msg, "CC8.1 exception")
	contains(msg, "expired")
}

test_missing_expiry_fails if {
	msgs := deny with input as {
		"change": {"outside_window": true},
		"as_of": "2026-09-13",
		"exception": {"reason": "synthetic window miss"},
	}
	some msg in msgs
	contains(msg, "CC8.1 exception")
	contains(msg, "missing expiry")
}
