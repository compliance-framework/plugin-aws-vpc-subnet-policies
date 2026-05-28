package compliance_framework.deny_privacy_public_routes

privacy_tag_key(key) if {
	configured := data.privacy_subnet_tag_keys[_]
	lower(key) == lower(configured)
}

privacy_tag_value(value) if {
	configured := data.privacy_subnet_tag_values[_]
	lower(value) == lower(configured)
}

privacy_scoped_subnet if {
	some tag in input.subnet.Tags
	privacy_tag_key(tag.Key)
	privacy_tag_value(tag.Value)
}

public_ipv4_destination(cidr) if {
	cidr == "0.0.0.0/0"
}

public_ipv6_destination(cidr) if {
	cidr == "::/0"
}

internet_gateway_target(route) if {
	startswith(object.get(route, "GatewayId", ""), "igw-")
}

public_internet_route(route) if {
	public_ipv4_destination(object.get(route, "DestinationCidrBlock", ""))
	internet_gateway_target(route)
}

public_internet_route(route) if {
	public_ipv6_destination(object.get(route, "DestinationIpv6CidrBlock", ""))
	internet_gateway_target(route)
}

privacy_public_route[route] if {
	privacy_scoped_subnet
	not data.allow_privacy_subnet_public_routes
	route_table := object.get(input.subnet_context, "route_table_for_subnet", null)
	route_table != null
	route := route_table.Routes[_]
	public_internet_route(route)
}

violation[{}] if {
	count(privacy_public_route) > 0
}

skip_reason := "Subnet is not privacy scoped" if {
	not privacy_scoped_subnet
}

title := "Privacy-scoped subnet should not have public internet routes" if {
	privacy_scoped_subnet
}

description := "Privacy-scoped subnets should not route default IPv4 or IPv6 traffic directly to an internet gateway unless explicitly allowed by policy data" if {
	privacy_scoped_subnet
}
