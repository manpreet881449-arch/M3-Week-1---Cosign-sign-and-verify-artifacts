package deploy

import rego.v1

good_input := {
    "image": "localhost:5000/sample-app:v1",
    "signature_verified": true,
    "vulnerabilities": {"critical": 0},
}

test_allow_good_image if {
    allow with input as good_input
}

test_allow_ghcr_image if {
    allow with input as object.union(good_input, {"image": "ghcr.io/manpreet881449-arch/sample-app:v1"})
}

test_deny_unsigned if {
    i := object.union(good_input, {"signature_verified": false})
    not allow with input as i
    "image signature missing or invalid" in deny with input as i
}

test_deny_critical_cves if {
    i := object.union(good_input, {"vulnerabilities": {"critical": 3}})
    not allow with input as i
    "image has 3 critical vulnerabilities" in deny with input as i
}

test_deny_untrusted_registry if {
    i := object.union(good_input, {"image": "docker.io/random/app:v1"})
    not allow with input as i
    "image is not from a trusted registry" in deny with input as i
}

test_deny_registry_prefix_trick if {
    i := object.union(good_input, {"image": "localhost:5000.evil.com/app:v1"})
    not allow with input as i
}

test_deny_missing_scan_data if {
    i := object.remove(good_input, ["vulnerabilities"])
    not allow with input as i
    "vulnerability scan data missing" in deny with input as i
}

test_deny_scan_value_is_string if {
    i := object.union(good_input, {"vulnerabilities": {"critical": "0"}})
    not allow with input as i
}
