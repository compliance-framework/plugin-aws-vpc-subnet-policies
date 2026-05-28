package compliance_framework.require_ip_capacity

cidr_prefix_length := prefix if {
	parts := split(input.subnet.CidrBlock, "/")
	count(parts) == 2
	prefix := to_number(parts[1])
}

total_ipv4_address_count := total if {
	prefix := cidr_prefix_length
	total := cidr_total_ipv4_address_counts[sprintf("%v", [prefix])]
}

cidr_total_ipv4_address_counts := {
	"0": 4294967296,
	"1": 2147483648,
	"2": 1073741824,
	"3": 536870912,
	"4": 268435456,
	"5": 134217728,
	"6": 67108864,
	"7": 33554432,
	"8": 16777216,
	"9": 8388608,
	"10": 4194304,
	"11": 2097152,
	"12": 1048576,
	"13": 524288,
	"14": 262144,
	"15": 131072,
	"16": 65536,
	"17": 32768,
	"18": 16384,
	"19": 8192,
	"20": 4096,
	"21": 2048,
	"22": 1024,
	"23": 512,
	"24": 256,
	"25": 128,
	"26": 64,
	"27": 32,
	"28": 16,
	"29": 8,
	"30": 4,
	"31": 2,
	"32": 1,
}

available_ip_count := count if {
	count := input.subnet.AvailableIpAddressCount
}

available_ip_count := count if {
	count := input.subnet_context.current.available_ip_address_count
}

available_ip_percentage := percentage if {
	total := total_ipv4_address_count
	total > 0
	percentage := (available_ip_count / total) * 100
}

violation[{}] if {
	available_ip_percentage < data.minimum_available_ip_address_percentage
}

title := "Subnet should maintain available IP address capacity"
description := sprintf("Subnet should have at least %v%% available IPv4 address capacity based on raw CIDR size", [data.minimum_available_ip_address_percentage])
