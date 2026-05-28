package compliance_framework.deny_public_ip_on_launch

test_violation_public_ip_on_launch_enabled if {
	count(violation) == 1 with input as {
		"subnet": {"MapPublicIpOnLaunch": true},
		"subnet_context": {"current": {"map_public_ip_on_launch": true}}
	}
}

test_no_violation_public_ip_on_launch_disabled if {
	count(violation) == 0 with input as {
		"subnet": {"MapPublicIpOnLaunch": false},
		"subnet_context": {"current": {"map_public_ip_on_launch": false}}
	}
}

test_no_violation_public_ip_on_launch_allowed if {
	count(violation) == 0 with input as {
		"subnet": {"MapPublicIpOnLaunch": true},
		"subnet_context": {"current": {"map_public_ip_on_launch": true}}
	} with data.allow_subnet_public_ip_on_launch as true
}
