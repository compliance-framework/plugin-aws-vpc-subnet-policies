package compliance_framework.deny_privacy_public_routes

risk_templates := [{
	"name": "Privacy-scoped subnet has direct public internet routing",
	"title": "Privacy Data Network Path Exposure",
	"statement": "A subnet identified as privacy-scoped that routes default IPv4 or IPv6 traffic directly to an internet gateway may expose systems handling personal or restricted information to unintended public network paths. This can increase the likelihood of unauthorized access paths or sensitive information exposure if other network controls are incomplete or misconfigured.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["subnet_privacy_public_route"],
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-200",
			"title": "Exposure of Sensitive Information to an Unauthorized Actor",
			"url": "https://cwe.mitre.org/data/definitions/200.html"
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-668",
			"title": "Exposure of Resource to Wrong Sphere",
			"url": "https://cwe.mitre.org/data/definitions/668.html"
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-284",
			"title": "Improper Access Control",
			"url": "https://cwe.mitre.org/data/definitions/284.html"
		}
	],
	"remediation": {
		"title": "Remove direct public routing from privacy-scoped subnets",
		"description": "Route privacy-scoped workloads through approved private or controlled egress paths and remove direct default routes to internet gateways unless an approved exception exists.",
		"tasks": [
			{"title": "Review the subnet route table for default routes to internet gateways"},
			{"title": "Move privacy-scoped workloads to private subnets where direct public internet routing is not present"},
			{"title": "Use NAT, VPC endpoints, private connectivity, or controlled ingress layers for required access paths"},
			{"title": "Validate security groups and NACLs for workloads remaining in internet-routed subnets"},
			{"title": "Document and approve any exception that allows direct public routing for privacy-scoped workloads"}
		]
	}
}]

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

violation[{"id": "subnet_privacy_public_route"}] if {
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
