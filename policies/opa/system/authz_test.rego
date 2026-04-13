# ==============================================================================
# CloudSentinel — System Authorization Policy Tests
# Verifies Zero Trust enforcement on the OPA PDP API surface.
#
# Run: opa test policies/opa -v
# ==============================================================================

package system.authz_test

import rego.v1

# ── Fixture: valid token ──────────────────────────────────────────────────────

_token := "test-secret-token-for-unit-tests-only-64chars-0123456789abcdef"

_token_data := {"opa_config": {"auth_token": _token}}

# ── TEST: Health endpoint is always open (no token) ──────────────────────────

test_health_allowed_without_token if {
	data.system.authz.allow
		with input as {"path": ["health"], "method": "GET"}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: Authenticated POST to /v1/data/ (policy evaluation) — allowed ──────

test_authenticated_eval_allowed if {
	data.system.authz.allow
		with input as {
			"path": ["v1", "data", "cloudsentinel", "gate", "decision"],
			"method": "POST",
			"identity": _token,
		}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: Authenticated GET on /v1/policies — allowed ────────────────────────

test_authenticated_policy_read_allowed if {
	data.system.authz.allow
		with input as {
			"path": ["v1", "policies"],
			"method": "GET",
			"identity": _token,
		}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: Unauthenticated POST to /v1/data/ — DENIED ────────────────────────

test_unauthenticated_eval_denied if {
	not data.system.authz.allow
		with input as {
			"path": ["v1", "data", "cloudsentinel", "gate", "decision"],
			"method": "POST",
		}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: Wrong token — DENIED ───────────────────────────────────────────────

test_wrong_token_denied if {
	not data.system.authz.allow
		with input as {
			"path": ["v1", "data", "cloudsentinel", "gate", "decision"],
			"method": "POST",
			"identity": "wrong-token-attacker-attempt",
		}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: PUT /v1/policies — DENIED (policy injection blocked) ───────────────
# This is the critical Zero Trust test: even with a valid token,
# writing policies via API is forbidden.

test_policy_injection_denied_with_valid_token if {
	not data.system.authz.allow
		with input as {
			"path": ["v1", "policies", "cloudsentinel", "bypass"],
			"method": "PUT",
			"identity": _token,
		}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: PUT /v1/data — DENIED (data tampering blocked) ─────────────────────

test_data_tampering_denied_with_valid_token if {
	not data.system.authz.allow
		with input as {
			"path": ["v1", "data", "cloudsentinel", "exceptions"],
			"method": "PUT",
			"identity": _token,
		}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: DELETE /v1/policies — DENIED ────────────────────────────────────────

test_policy_deletion_denied if {
	not data.system.authz.allow
		with input as {
			"path": ["v1", "policies", "cloudsentinel", "gate"],
			"method": "DELETE",
			"identity": _token,
		}
		with data.opa_config as _token_data.opa_config
}

# ── TEST: No token config loaded — all non-health denied ─────────────────────
# If opa_auth_config.json is missing, _expected_token is undefined,
# which means _token_valid is false → everything except /health is blocked.

test_missing_token_config_denies_all if {
	not data.system.authz.allow
		with input as {
			"path": ["v1", "data", "cloudsentinel", "gate", "decision"],
			"method": "POST",
			"identity": "any-token",
		}
		with data.opa_config as {}
}
