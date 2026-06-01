package compliance_framework.require_flow_log_coverage

risk_templates := [{
	"name": "Subnet lacks approved flow log coverage",
	"title": "Insufficient Network Activity Visibility",
	"statement": "When a subnet is not covered by approved VPC or subnet flow logs, network activity for resources in that subnet may not be captured with enough detail for detection, investigation, or compliance evidence. This reduces visibility into unauthorized access attempts, unexpected traffic paths, and incident response context.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"violation_ids": ["subnet_flow_log_coverage_missing"],
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-778",
			"title": "Insufficient Logging",
			"url": "https://cwe.mitre.org/data/definitions/778.html"
		}
	],
	"remediation": {
		"title": "Enable approved subnet network flow logging",
		"description": "Ensure the subnet is covered by active VPC or subnet flow logs using the traffic types required by policy data.",
		"tasks": [
			{"title": "Enable a VPC-level or subnet-level flow log that covers the subnet"},
			{"title": "Configure the flow log traffic type to match the approved baseline, such as ALL where required"},
			{"title": "Verify the flow log status is active and delivery is healthy"},
			{"title": "Confirm the log destination is retained and monitored according to logging policy"},
			{"title": "Re-run evidence collection to confirm coverage is detected"}
		]
	}
}]

approved_flow_log_status(status) if {
	approved := data.approved_subnet_flow_log_statuses[_]
	upper(status) == upper(approved)
}

required_flow_log_traffic_type(traffic_type) if {
	required := data.required_subnet_flow_log_traffic_types[_]
	upper(traffic_type) == upper(required)
}

approved_flow_log_delivery_status(status) if {
	approved := data.approved_subnet_flow_log_delivery_statuses[_]
	upper(status) == upper(approved)
}

flow_log_approved(flow_log) if {
	approved_flow_log_status(object.get(flow_log, "FlowLogStatus", ""))
	required_flow_log_traffic_type(object.get(flow_log, "TrafficType", ""))
	approved_flow_log_delivery_status(object.get(flow_log, "DeliverLogsStatus", ""))
}

vpc_flow_log_coverage if {
	flow_log := input.subnet_context.flow_logs_for_vpc[_]
	flow_log_approved(flow_log)
}

subnet_flow_log_coverage if {
	flow_log := input.subnet_context.flow_logs_for_subnet[_]
	flow_log_approved(flow_log)
}

violation[{"id": "subnet_flow_log_coverage_missing"}] if {
	not vpc_flow_log_coverage
	not subnet_flow_log_coverage
}

title := "Subnet should have flow log coverage"
description := sprintf("Subnet should be covered by VPC or subnet flow logs with approved statuses: %s, delivery statuses: %s, and traffic types: %s", [concat(", ", data.approved_subnet_flow_log_statuses), concat(", ", data.approved_subnet_flow_log_delivery_statuses), concat(", ", data.required_subnet_flow_log_traffic_types)])
