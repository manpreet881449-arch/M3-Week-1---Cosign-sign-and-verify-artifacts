package deploy

import rego.v1

default allow := false

allow if count(deny) == 0

trusted_registries := {"localhost:5000/", "ghcr.io/manpreet881449-arch/"}

from_trusted_registry if {
    some r in trusted_registries
    startswith(input.image, r)
}

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
