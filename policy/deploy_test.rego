package deploy

import rego.v1

d := "sha256:2946df84c6516b588d1a5c256d6b319232a5f4af6134b8044a33f1c77ea20a06"

good_input := {
    "image": sprintf("localhost:5000/sample-app@%s", [d]),
    "signature_verified": true,
    "vulnerabilities": {"critical": 0},
    "sbom_attested": true,
    "base_image": "alpine:3.20",
    "terraform_scan_passed": true,
}

test_allow_good_image if { allow with input as good_input }

test_allow_ghcr_image if {
    i := object.union(good_input, {"image": sprintf("ghcr.io/manpreet881449-arch/sample-app@%s", [d])})
    allow with input as i
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
    i := object.union(good_input, {"image": sprintf("docker.io/random/app@%s", [d])})
    not allow with input as i
    "image is not from a trusted registry" in deny with input as i
}

test_deny_registry_prefix_trick if {
    i := object.union(good_input, {"image": sprintf("localhost:5000.evil.com/app@%s", [d])})
    not allow with input as i
    "image is not from a trusted registry" in deny with input as i
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

test_deny_latest_tag if {
    i := object.union(good_input, {"image": "localhost:5000/sample-app:latest"})
    not allow with input as i
    "image uses the :latest tag" in deny with input as i
}

test_deny_tag_without_digest if {
    i := object.union(good_input, {"image": "localhost:5000/sample-app:v1"})
    not allow with input as i
    "image must be referenced by digest (@sha256:...)" in deny with input as i
}

test_deny_sbom_not_attested if {
    i := object.union(good_input, {"sbom_attested": false})
    not allow with input as i
    "SBOM attestation missing or invalid" in deny with input as i
}

test_deny_sbom_field_missing if {
    i := object.remove(good_input, ["sbom_attested"])
    not allow with input as i
}

test_deny_unapproved_base_image if {
    i := object.union(good_input, {"base_image": "ubuntu:latest"})
    not allow with input as i
    "base image is not in the approved list" in deny with input as i
}

test_deny_base_image_missing if {
    i := object.remove(good_input, ["base_image"])
    not allow with input as i
}

test_deny_terraform_scan_failed if {
    i := object.union(good_input, {"terraform_scan_passed": false})
    not allow with input as i
    "terraform scan failed or did not run" in deny with input as i
}

test_deny_terraform_scan_missing if {
    i := object.remove(good_input, ["terraform_scan_passed"])
    not allow with input as i
}
