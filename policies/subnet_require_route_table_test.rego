package compliance_framework.require_route_table

test_no_violation_explicit_route_table if {
	count(violation) == 0 with input as {
		"subnet_context": {"route_table_for_subnet": {"RouteTableId": "rtb-explicit"}, "explicit_route_table_association": true}
	}
}

test_no_violation_main_route_table_fallback if {
	count(violation) == 0 with input as {
		"subnet_context": {"route_table_for_subnet": {"RouteTableId": "rtb-main"}, "explicit_route_table_association": false}
	}
}

test_violation_no_route_table if {
	count(violation) == 1 with input as {
		"subnet_context": {"route_table_for_subnet": null, "explicit_route_table_association": false}
	}
}
