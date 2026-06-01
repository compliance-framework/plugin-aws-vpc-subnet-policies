package compliance_framework.require_flow_log_coverage

test_no_violation_vpc_flow_log_covers_subnet if {
	count(violation) == 0 with input as {
		"subnet_context": {"flow_logs_for_vpc": [{"FlowLogStatus": "ACTIVE", "TrafficType": "ALL", "DeliverLogsStatus": "SUCCESS"}], "flow_logs_for_subnet": []}
	}
}

test_no_violation_subnet_flow_log_covers_subnet if {
	count(violation) == 0 with input as {
		"subnet_context": {"flow_logs_for_vpc": [], "flow_logs_for_subnet": [{"FlowLogStatus": "ACTIVE", "TrafficType": "ALL", "DeliverLogsStatus": "SUCCESS"}]}
	}
}

test_violation_no_flow_log_coverage if {
	count(violation) == 1 with input as {
		"subnet_context": {"flow_logs_for_vpc": [], "flow_logs_for_subnet": []}
	}
}

test_violation_inactive_flow_log if {
	count(violation) == 1 with input as {
		"subnet_context": {"flow_logs_for_vpc": [{"FlowLogStatus": "FAILED", "TrafficType": "ALL", "DeliverLogsStatus": "SUCCESS"}], "flow_logs_for_subnet": []}
	}
}

test_violation_accept_only_flow_log if {
	count(violation) == 1 with input as {
		"subnet_context": {"flow_logs_for_vpc": [{"FlowLogStatus": "ACTIVE", "TrafficType": "ACCEPT", "DeliverLogsStatus": "SUCCESS"}], "flow_logs_for_subnet": []}
	}
}

test_violation_failed_flow_log_delivery if {
	count(violation) == 1 with input as {
		"subnet_context": {"flow_logs_for_vpc": [{"FlowLogStatus": "ACTIVE", "TrafficType": "ALL", "DeliverLogsStatus": "FAILED"}], "flow_logs_for_subnet": []}
	}
}

test_no_violation_custom_required_traffic_type if {
	count(violation) == 0 with input as {
		"subnet_context": {"flow_logs_for_vpc": [{"FlowLogStatus": "ACTIVE", "TrafficType": "REJECT", "DeliverLogsStatus": "SUCCESS"}], "flow_logs_for_subnet": []}
	} with data.required_subnet_flow_log_traffic_types as ["REJECT"]
}
