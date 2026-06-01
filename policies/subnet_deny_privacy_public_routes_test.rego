package compliance_framework.deny_privacy_public_routes

test_skip_non_privacy_subnet if {
	input_value := {
		"subnet": {"Tags": [{"Key": "Environment", "Value": "prod"}]},
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}]}}
	}
	skip_reason == "Subnet is not privacy scoped" with input as input_value
	count(violation) == 0 with input as input_value
	not title with input as input_value
	not description with input as input_value
}

test_violation_privacy_subnet_public_ipv4_route if {
	count(violation) == 1 with input as {
		"subnet": {"Tags": [{"Key": "data-classification", "Value": "personal"}]},
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}]}}
	}
}

test_no_violation_privacy_subnet_blackhole_public_ipv4_route if {
	count(violation) == 0 with input as {
		"subnet": {"Tags": [{"Key": "data-classification", "Value": "personal"}]},
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123", "State": "blackhole"}]}}
	}
}

test_violation_privacy_subnet_public_ipv6_route if {
	count(violation) == 1 with input as {
		"subnet": {"Tags": [{"Key": "confidentiality", "Value": "restricted"}]},
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-123"}]}}
	}
}

test_no_violation_privacy_subnet_private_route if {
	count(violation) == 0 with input as {
		"subnet": {"Tags": [{"Key": "data-classification", "Value": "personal"}]},
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationCidrBlock": "10.0.0.0/8", "GatewayId": "local"}]}}
	}
}

test_no_violation_privacy_subnet_public_route_allowed if {
	count(violation) == 0 with input as {
		"subnet": {"Tags": [{"Key": "data-classification", "Value": "personal"}]},
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123"}]}}
	} with data.allow_privacy_subnet_public_routes as true
}
