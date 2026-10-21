package deploy

import rego.v1

default allow := false

allow if count(deny) == 0

trusted_registries := {"localhost:5000/", "ghcr.io/manpreet881449-arch/"}

approved_base_images := {"alpine:3.20", "python:3.12-alpine"}

from_trusted_registry if {
    some r in trusted_registries
    startswith(input.image, r)
}

has_digest if regex.match(`@sha256:[a-f0-9]{64}$`, input.image)

scan_data_present if is_number(input.vulnerabilities.critical)

deny contains msg if {
    not input.signature_verified
    msg := "image signature missing or invalid"
}

deny contains msg if {
    not scan_data_present
    msg := "vulnerability scan data missing"
}

deny contains msg if {
    input.vulnerabilities.critical > 0
    msg := sprintf("image has %d critical vulnerabilities", [input.vulnerabilities.critical])
}

deny contains msg if {
    not from_trusted_registry
    msg := "image is not from a trusted registry"
}

deny contains msg if {
    endswith(input.image, ":latest")
    msg := "image uses the :latest tag"
}

deny contains msg if {
    not has_digest
    msg := "image must be referenced by digest (@sha256:...)"
}

deny contains msg if {
    not input.sbom_attested
    msg := "SBOM attestation missing or invalid"
}

deny contains msg if {
    not input.base_image in approved_base_images
    msg := "base image is not in the approved list"
}

deny contains msg if {
    not input.terraform_scan_passed
    msg := "terraform scan failed or did not run"
}

deny contains msg if {
    not input.base_image
    msg := "base image not provided"
}
