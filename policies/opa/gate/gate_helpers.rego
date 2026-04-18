package cloudsentinel.gate

import rego.v1

# Path normalization and boolean coercion (module 2/8)

normalize_path(path) := normalized if {
	type_name(path) == "string"
	p1 := replace(path, "\\", "/")
	p2 := replace(p1, "/./", "/")
	p3 := replace(p2, "//", "/")
	p4 := trim_prefix(p3, "./")
	normalized := trim(p4, "/")
}

normalize_path(path) := "" if {
	type_name(path) != "string"
}

to_bool(v) := b if {
	type_name(v) == "boolean"
	b := v
}

to_bool(v) if {
	type_name(v) == "string"
	vv := lower(trim_space(v))
	vv == "true"
}

to_bool(v) if {
	type_name(v) == "string"
	vv := lower(trim_space(v))
	vv == "1"
}

to_bool(v) := false if {
	type_name(v) == "string"
	vv := lower(trim_space(v))
	vv == "false"
}

to_bool(v) := false if {
	type_name(v) == "string"
	vv := lower(trim_space(v))
	vv == "0"
}

to_bool(v) := false if {
	type_name(v) != "boolean"
	type_name(v) != "string"
}
