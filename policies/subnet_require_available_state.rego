package compliance_framework.require_available_state

approved_state(state) if {
	approved := data.approved_subnet_states[_]
	lower(state) == lower(approved)
}

violation[{}] if {
	not approved_state(input.subnet.State)
}

title := "Subnet should be in an approved state"
description := sprintf("Subnet state should match one of the approved states: %s", [concat(", ", data.approved_subnet_states)])
