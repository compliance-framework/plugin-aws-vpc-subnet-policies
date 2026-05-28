package compliance_framework.deny_public_ip_on_launch

map_public_ip_on_launch if {
	input.subnet.MapPublicIpOnLaunch == true
}

map_public_ip_on_launch if {
	input.subnet_context.current.map_public_ip_on_launch == true
}

violation[{}] if {
	not data.allow_subnet_public_ip_on_launch
	map_public_ip_on_launch
}

title := "Subnet should not auto-assign public IP addresses on launch"
description := "Subnet MapPublicIpOnLaunch should be disabled unless public IP assignment on launch is explicitly allowed by policy data"
