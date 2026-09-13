package storage.encryption

import rego.v1

test_kms_passes if {
	count(deny) == 0 with input as {"objects": [{"name": "synthetic-object", "encryption": "aws:kms"}]}
}

test_empty_passes if {
	count(deny) == 0 with input as {"objects": []}
}

test_aes256_fails if {
	msgs := deny with input as {"objects": [{"name": "synthetic-object", "encryption": "AES256"}]}
	some msg in msgs
	contains(msg, "CC6.1 encryption")
	contains(msg, "aws:kms")
}

test_missing_encryption_fails if {
	msgs := deny with input as {"objects": [{"name": "synthetic-object"}]}
	some msg in msgs
	contains(msg, "CC6.1 encryption")
	contains(msg, "missing")
}
