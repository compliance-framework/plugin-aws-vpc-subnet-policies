package compliance_framework.require_tags

required_tag[tag] if {
	tag := data.required_subnet_tags[_]
}

missing_tag[tag] if {
	required_tag[tag]
	not tag_exists(input.subnet.Tags, tag)
}

violation[{}] if {
	count(missing_tag) > 0
}

tag_exists(tags, tag_name) if {
	some tag in tags
	lower(tag.Key) == lower(tag_name)
}

title := "Subnet should set required tags"
description := sprintf("Subnet tags should contain required tag keys: %s", [concat(", ", data.required_subnet_tags)])
