package change.exception

import rego.v1

# A change inside the window needs no exception.
# A change outside the window passes only when exception.reason is set and
# exception.expires is a YYYY-MM-DD date on or after input.as_of.
# Dates are compared as strings. They must be zero-padded.

date_pattern := `^[0-9]{4}-[0-9]{2}-[0-9]{2}$`

reason(doc) := object.get(object.get(doc, "exception", {}), "reason", "")

expires(doc) := object.get(object.get(doc, "exception", {}), "expires", "")

deny contains msg if {
	input.change.outside_window == true
	reason(input) == ""
	msg := "CC8.1 exception: missing reason"
}

deny contains msg if {
	input.change.outside_window == true
	reason(input) != ""
	expires(input) == ""
	msg := "CC8.1 exception: missing expiry"
}

deny contains msg if {
	input.change.outside_window == true
	expires(input) != ""
	not regex.match(date_pattern, expires(input))
	msg := sprintf("CC8.1 exception: expiry must be YYYY-MM-DD, got %q", [expires(input)])
}

deny contains msg if {
	input.change.outside_window == true
	object.get(input, "as_of", "") == ""
	msg := "CC8.1 exception: missing as_of date"
}

deny contains msg if {
	input.change.outside_window == true
	regex.match(date_pattern, expires(input))
	regex.match(date_pattern, object.get(input, "as_of", ""))
	expires(input) < input.as_of
	msg := sprintf("CC8.1 exception: expired (expires %s, as of %s)", [expires(input), input.as_of])
}
