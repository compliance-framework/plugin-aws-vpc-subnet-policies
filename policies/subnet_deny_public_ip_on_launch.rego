package compliance_framework.deny_public_ip_on_launch

risk_templates := [{
	"name": "Subnet public IP assignment on launch enabled",
	"title": "Automatic Public Network Exposure for New Workloads",
	"statement": "When a subnet automatically assigns public IP addresses on launch, newly created workloads can receive direct public network reachability by default. This increases the chance that systems are exposed outside their intended control sphere before security group, routing, or workload hardening controls are fully validated.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["subnet_public_ip_on_launch"],
	"threat_refs": [
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
		"title": "Disable automatic public IP assignment",
		"description": "Disable automatic public IP assignment on the subnet unless it is explicitly required for the subnet design, and route internet access through approved boundary patterns.",
		"tasks": [
			{"title": "Set MapPublicIpOnLaunch to false for the subnet"},
			{"title": "Review workloads launched in the subnet for existing public IP addresses"},
			{"title": "Use private subnets with NAT, load balancers, or approved ingress paths where public addressing is not required"},
			{"title": "Confirm security groups and NACLs restrict any remaining public-facing workloads"},
			{"title": "Document any subnet where automatic public IP assignment remains explicitly allowed"}
		]
	}
}]

map_public_ip_on_launch if {
	input.subnet.MapPublicIpOnLaunch == true
}

map_public_ip_on_launch if {
	input.subnet_context.current.map_public_ip_on_launch == true
}

violation[{"id": "subnet_public_ip_on_launch"}] if {
	not data.allow_subnet_public_ip_on_launch
	map_public_ip_on_launch
}

title := "Subnet should not auto-assign public IP addresses on launch"
description := "Subnet MapPublicIpOnLaunch should be disabled unless public IP assignment on launch is explicitly allowed by policy data"
