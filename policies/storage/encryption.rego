package storage.encryption

import rego.v1

# Synthetic object-storage plan. Not a live bucket and not a customer name.
# Passes only when every object uses SSE-KMS (aws:kms).

deny contains msg if {
	some obj in input.objects
	got := object.get(obj, "encryption", "missing")
	got != "aws:kms"
	msg := sprintf("CC6.1 encryption: object %q must use SSE-KMS (aws:kms), got %q", [object.get(obj, "name", "(unnamed)"), got])
}
