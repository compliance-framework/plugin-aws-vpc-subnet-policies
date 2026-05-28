package compliance_framework.require_tags

test_violation_missing_required_subnet_tags if {
	count(violation) == 1 with input as {
		"subnet": {"Tags": [{"Key": "Environment", "Value": "prod"}]}
	}
}

test_no_violation_required_subnet_tags_present if {
	count(violation) == 0 with input as {
		"subnet": {"Tags": [
			{"Key": "Environment", "Value": "prod"},
			{"Key": "Owner", "Value": "platform"},
			{"Key": "compliance", "Value": "true"},
			{"Key": "confidentiality", "Value": "internal"}
		]}
	}
}

test_no_violation_custom_required_subnet_tags_present if {
	count(violation) == 0 with input as {
		"subnet": {"Tags": [{"Key": "cost-center", "Value": "1234"}]}
	} with data.required_subnet_tags as ["cost-center"]
}
