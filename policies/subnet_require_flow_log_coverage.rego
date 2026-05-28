package compliance_framework.require_flow_log_coverage

approved_flow_log_status(status) if {
	approved := data.approved_subnet_flow_log_statuses[_]
	upper(status) == upper(approved)
}

required_flow_log_traffic_type(traffic_type) if {
	required := data.required_subnet_flow_log_traffic_types[_]
	upper(traffic_type) == upper(required)
}

flow_log_approved(flow_log) if {
	approved_flow_log_status(object.get(flow_log, "FlowLogStatus", ""))
	required_flow_log_traffic_type(object.get(flow_log, "TrafficType", ""))
}

vpc_flow_log_coverage if {
	flow_log := input.subnet_context.flow_logs_for_vpc[_]
	flow_log_approved(flow_log)
}

subnet_flow_log_coverage if {
	flow_log := input.subnet_context.flow_logs_for_subnet[_]
	flow_log_approved(flow_log)
}

violation[{}] if {
	not vpc_flow_log_coverage
	not subnet_flow_log_coverage
}

title := "Subnet should have flow log coverage"
description := sprintf("Subnet should be covered by VPC or subnet flow logs with approved statuses: %s and traffic types: %s", [concat(", ", data.approved_subnet_flow_log_statuses), concat(", ", data.required_subnet_flow_log_traffic_types)])
