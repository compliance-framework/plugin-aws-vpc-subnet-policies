package compliance_framework.require_route_table

route_table_available if {
	object.get(input.subnet_context, "route_table_for_subnet", null) != null
}

violation[{}] if {
	not route_table_available
}

title := "Subnet should have route table coverage"
description := "Subnet should resolve to an explicit route-table association or the VPC main route-table fallback"
