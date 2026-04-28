# ==============================================================================
# Shift-Right Prowler — exceptions store
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

default _prowler_exceptions_store := {}

_prowler_exceptions_store := data.cloudsentinel.prowler_exceptions
