package cloudsentinel.gate

import rego.v1

# Finding accessors for exception matching (module 3/8)

finding_rule_id(f) := upper(trim_space(object.get(object.get(f, "source", {}), "id", "")))
finding_tool(f) := lower(trim_space(object.get(object.get(f, "source", {}), "tool", "")))

finding_resource_id(f) := rid if {
	rid := normalize_path(object.get(object.get(f, "resource", {}), "name", ""))
	rid != ""
}

finding_resource_id(f) := rid if {
	normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
	rid := normalize_path(object.get(object.get(f, "resource", {}), "path", ""))
	rid != ""
}

finding_resource_id(f) := rid if {
	normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
	normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
	rid := normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", ""))
	rid != ""
}

finding_resource_id(f) := "" if {
	normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
	normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
	normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", "")) == ""
}

finding_occurrence_file(f) := file if {
	file := normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", ""))
	file != ""
}

finding_occurrence_file(f) := file if {
	normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", "")) == ""
	file := normalize_path(object.get(object.get(f, "resource", {}), "path", ""))
	file != ""
}

finding_occurrence_file(f) := file if {
	normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", "")) == ""
	normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
	file := normalize_path(object.get(object.get(f, "resource", {}), "name", ""))
	file != ""
}

finding_occurrence_file(f) := "" if {
	normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", "")) == ""
	normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
	normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
}

finding_occurrence_line(f) := line if {
	raw := object.get(object.get(object.get(f, "resource", {}), "location", {}), "start_line", 0)
	type_name(raw) == "number"
	line := raw
}

finding_occurrence_line(f) := line if {
	raw := object.get(object.get(object.get(f, "resource", {}), "location", {}), "start_line", 0)
	type_name(raw) == "string"
	trim_space(raw) != ""
	line := to_number(raw)
}

finding_occurrence_line(f) := 0 if {
	raw := object.get(object.get(object.get(f, "resource", {}), "location", {}), "start_line", 0)
	type_name(raw) == "string"
	trim_space(raw) == ""
}

finding_occurrence_line(f) := 0 if {
	raw := object.get(object.get(object.get(f, "resource", {}), "location", {}), "start_line", 0)
	type_name(raw) != "number"
	type_name(raw) != "string"
}

finding_severity_level(f) := upper(trim_space(object.get(object.get(f, "severity", {}), "level", "LOW")))
