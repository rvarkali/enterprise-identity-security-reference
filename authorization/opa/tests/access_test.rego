package iam.access_test

import rego.v1
import data.iam.access

project := {"resource_type": "project", "action": "can_view", "openfga_allowed": true, "authentication": {}}
document := object.union(project, {"resource_type": "document", "classification": "INTERNAL"})
confidential := object.union(document, {"classification": "CONFIDENTIAL"})
# Synthetic unit-test value only. It is not a claim mapping or deployed MFA configuration.
verified := object.union(confidential, {"authentication": {"assurance": "test:verified-mfa"}})

test_projects_allow_all_supported_actions if {
  every action in ["can_view", "can_edit", "can_delete"] {
    access.allow with input as object.union(project, {"action": action})
  }
}

test_public_internal_allow_all_supported_actions if {
  every classification in ["PUBLIC", "INTERNAL"] {
    every action in ["can_view", "can_edit", "can_delete"] {
      access.allow with input as object.union(document, {"classification": classification, "action": action})
    }
  }
}

test_unknown_assurance_is_not_required_for_public_internal_projects if {
  every base in [project, document, object.union(document, {"classification": "PUBLIC"})] {
    access.allow with input as object.union(base, {"authentication": {"assurance": "unknown"}})
  }
}

test_confidential_denied_with_shipped_configuration if {
  not access.allow with input as verified
}

test_confidential_allows_only_explicitly_configured_value if {
  every action in ["can_view", "can_edit", "can_delete"] {
    access.allow with input as object.union(verified, {"action": action})
      with data.iam.config.trusted_assurance_values as ["test:verified-mfa"]
  }
}

test_confidential_missing_unknown_assurance_denied if {
  every authentication in [{}, {"assurance": "unknown"}, {"assurance": "1"}, {"assurance": "2"}, {"assurance": "mfa"}] {
    not access.allow with input as object.union(confidential, {"authentication": authentication})
      with data.iam.config.trusted_assurance_values as ["test:verified-mfa"]
  }
}

test_missing_classification_denied if {
  not access.allow with input as object.remove(document, {"classification"})
}

test_unknown_or_malformed_classification_denied if {
  every classification in ["restricted", "internal", "", "UNKNOWN", null, true, 1, [], {}] {
    not access.allow with input as object.union(document, {"classification": classification})
  }
}

test_unknown_or_malformed_resource_types_denied if {
  every resource_type in ["tenant", "", "PROJECT", null, true, 1, [], {}] {
    not access.allow with input as object.union(project, {"resource_type": resource_type})
  }
}

test_unknown_or_malformed_actions_denied if {
  every action in ["read", "can_manage", "", null, true, 1, [], {}] {
    not access.allow with input as object.union(project, {"action": action})
  }
}

test_missing_required_context_denied if {
  every key in ["resource_type", "action", "openfga_allowed", "authentication"] {
    not access.allow with input as object.remove(project, {key})
  }
}

test_missing_input_denied if {
  not access.allow
}

test_malformed_top_level_input_denied if {
  every malformed in [null, true, false, 0, "document", [], [{}], {}] {
    not access.allow with input as malformed
  }
}

test_malformed_authentication_denied if {
  every authentication in [null, true, "mfa", 1, [], {"assurance": null}, {"assurance": []},
                          {"assurance": {}}, {"assurance": true}, {"assurance": 2}, {"assurance": ""}] {
    not access.allow with input as object.union(project, {"authentication": authentication})
  }
}

test_extra_input_fields_denied if {
  not access.allow with input as object.union(project, {"classification": "PUBLIC"})
  not access.allow with input as object.union(project, {"trusted_assurance_values": ["mfa"]})
  not access.allow with input as object.union(project, {"authentication": {"assurance": "mfa", "trusted": true}})
}

test_openfga_denial_or_malformed_result_cannot_be_overridden if {
  every result in [false, null, "true", 1, {}, []] {
    every base in [project, document, verified] {
      not access.allow with input as object.union(base, {"openfga_allowed": result})
        with data.iam.config.trusted_assurance_values as ["test:verified-mfa"]
    }
  }
}

test_missing_configuration_denies_confidential if {
  not access.allow with input as verified with data.iam.config as {}
}

test_invalid_configuration_denies_confidential if {
  every config in [null, true, "test:verified-mfa", {}, [1], [""], ["test:verified-mfa", null]] {
    not access.allow with input as verified with data.iam.config.trusted_assurance_values as config
  }
}

test_raw_claims_and_jwt_presence_do_not_establish_assurance if {
  every context in [{"acr": "2"}, {"amr": ["pwd", "otp"]}, {"jwt_present": true}, {"mfa": true}] {
    not access.allow with input as object.union(confidential, {"authentication": context})
      with data.iam.config.trusted_assurance_values as ["test:verified-mfa"]
  }
}

test_legacy_agent_sketch_does_not_bypass_contract if {
  not access.allow with input as {"authenticated": true, "principal_active": true,
    "tenant_membership_active": true, "tenant_match": true, "openfga_allowed": true,
    "resource_classification": "internal", "delegation_required": false}
}
