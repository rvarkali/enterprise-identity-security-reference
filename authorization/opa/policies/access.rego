package iam.access

import rego.v1

default allow := false

# All input is built by the backend after authentication, tenant and OpenFGA checks.
# This decision is an additional gate, never an alternative to those checks.
valid_common if {
  is_object(input)
  input.resource_type in {"project", "document"}
  input.action in {"can_view", "can_edit", "can_delete"}
  input.openfga_allowed == true
  is_object(input.authentication)
  object.keys(input.authentication) - {"assurance"} == set()
  every key, value in input.authentication {
    key == "assurance"
    is_string(value)
    count(value) > 0
  }
}

allow if {
  valid_common
  input.resource_type == "project"
  object.keys(input) == {"resource_type", "action", "openfga_allowed", "authentication"}
}

valid_document if {
  valid_common
  input.resource_type == "document"
  object.keys(input) == {"resource_type", "action", "classification", "openfga_allowed", "authentication"}
  input.classification in {"PUBLIC", "INTERNAL", "CONFIDENTIAL"}
}

allow if {
  valid_document
  input.classification in {"PUBLIC", "INTERNAL"}
}

allow if {
  valid_document
  input.classification == "CONFIDENTIAL"
  trusted := data.iam.config.trusted_assurance_values
  is_array(trusted)
  every value in trusted {
    is_string(value)
    count(value) > 0
  }
  input.authentication.assurance in trusted
}
