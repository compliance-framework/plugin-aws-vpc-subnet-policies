package compliance_framework.deny_blackhole_routes

test_no_violation_active_routes if {
	count(violation) == 0 with input as {
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123", "State": "active"}]}}
	}
}

test_violation_blackhole_route if {
	count(violation) == 1 with input as {
		"subnet_context": {"route_table_for_subnet": {"Routes": [{"DestinationCidrBlock": "10.2.0.0/16", "TransitGatewayId": "tgw-123", "State": "blackhole"}]}}
	}
}

test_no_violation_missing_route_table if {
	count(violation) == 0 with input as {
		"subnet_context": {"route_table_for_subnet": null}
	}
}
