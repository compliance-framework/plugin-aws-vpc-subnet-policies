package compliance_framework.deny_blackhole_routes

blackhole_route[route] if {
	route_table := object.get(input.subnet_context, "route_table_for_subnet", null)
	route_table != null
	route := route_table.Routes[_]
	lower(object.get(route, "State", "")) == "blackhole"
}

violation[{}] if {
	count(blackhole_route) > 0
}

title := "Subnet effective route table should not contain blackhole routes"
description := "Subnet effective route table routes should not be in blackhole state because affected traffic cannot reach the configured route target"
