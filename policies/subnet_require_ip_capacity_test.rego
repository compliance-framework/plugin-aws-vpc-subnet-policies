package compliance_framework.require_ip_capacity

test_no_violation_available_ip_percentage_above_threshold if {
	count(violation) == 0 with input as {
		"subnet": {"CidrBlock": "10.0.1.0/24", "AvailableIpAddressCount": 30},
		"subnet_context": {"current": {"available_ip_address_count": 30}}
	}
}

test_violation_available_ip_percentage_below_threshold if {
	count(violation) == 1 with input as {
		"subnet": {"CidrBlock": "10.0.1.0/24", "AvailableIpAddressCount": 20},
		"subnet_context": {"current": {"available_ip_address_count": 20}}
	}
}

test_no_violation_custom_available_ip_percentage_threshold if {
	count(violation) == 0 with input as {
		"subnet": {"CidrBlock": "10.0.1.0/24", "AvailableIpAddressCount": 20},
		"subnet_context": {"current": {"available_ip_address_count": 20}}
	} with data.minimum_available_ip_address_percentage as 5
}

test_violation_small_subnet_percentage_below_threshold if {
	count(violation) == 1 with input as {
		"subnet": {"CidrBlock": "10.0.1.0/28", "AvailableIpAddressCount": 1},
		"subnet_context": {"current": {"available_ip_address_count": 1}}
	}
}

test_no_violation_small_subnet_percentage_above_threshold if {
	count(violation) == 0 with input as {
		"subnet": {"CidrBlock": "10.0.1.0/28", "AvailableIpAddressCount": 2},
		"subnet_context": {"current": {"available_ip_address_count": 2}}
	}
}
