package compliance_framework.require_available_state

test_no_violation_available_state if {
	count(violation) == 0 with input as {
		"subnet": {"State": "available"}
	}
}

test_violation_non_available_state if {
	count(violation) == 1 with input as {
		"subnet": {"State": "pending"}
	}
}

test_no_violation_custom_approved_state if {
	count(violation) == 0 with input as {
		"subnet": {"State": "pending"}
	} with data.approved_subnet_states as ["pending"]
}
