# ==============================================================================
# CloudSentinel — OPA System Authorization Policy (Zero Trust PDP Hardening)
#
# PURPOSE:
#   Prevent unauthorized access to the OPA Policy Decision Point.
#   This policy is loaded via --authorization=basic and evaluated on EVERY
#   incoming HTTP request before OPA processes it.
#
# SECURITY MODEL:
#   1. Health checks (/health) are always allowed (unauthenticated) — required
#      by Docker healthcheck and load balancers.
#   2. Read operations (GET, POST to /v1/data/) require a valid Bearer token.
#      POST to /v1/data/ is a READ in OPA semantics (policy evaluation with input).
#   3. ALL write operations (PUT/PATCH/DELETE to /v1/policies or /v1/data) are
#      DENIED unconditionally — policies are loaded from filesystem only.
#      This eliminates the Policy Injection attack vector entirely.
#
# TOKEN MANAGEMENT:
#   The token is injected via OPA_AUTH_TOKEN environment variable.
#   In CI: set as a masked GitLab CI/CD variable.
#   Locally: set in .env file (never committed).
#
# REFERENCE: NIST SP 800-207 (Zero Trust Architecture), Section 3 — PDP integrity.
# ==============================================================================

package system.authz

import rego.v1

default allow := false

# --- Health & readiness probes — always open (no token required) ---
# Docker healthcheck, Kubernetes liveness/readiness, and monitoring systems
# need unauthenticated access to /health. This is standard OPA practice.
allow if {
	input.path == ["health"]
}

# --- Token validation ---
# OPA --authentication=token extracts Bearer token from Authorization header
# and exposes it as input.identity. We compare against the expected token
# loaded from data.opa_config.auth_token (mounted as a JSON data file).
_expected_token := data.opa_config.auth_token

_token_valid if {
	_expected_token != ""
	input.identity == _expected_token
}

# --- Read operations with valid token ---
# POST /v1/data/... is OPA's evaluation endpoint (sends input, gets decision).
# This is a READ operation despite being POST — it does not modify state.
allow if {
	_token_valid
	input.method == "POST"
	input.path[0] == "v1"
	input.path[1] == "data"
}

# GET on /v1/data/ — read current data documents (debugging, audit)
allow if {
	_token_valid
	input.method == "GET"
	input.path[0] == "v1"
	input.path[1] == "data"
}

# GET on /v1/policies — read loaded policies (audit only)
allow if {
	_token_valid
	input.method == "GET"
	input.path[0] == "v1"
	input.path[1] == "policies"
}

# --- DENY all write operations — no exception possible ---
# PUT /v1/policies/...  → Policy Injection vector  → BLOCKED
# PATCH /v1/data/...    → Data Tampering vector    → BLOCKED
# DELETE /v1/policies/  → Policy Deletion vector   → BLOCKED
# DELETE /v1/data/      → Data Deletion vector     → BLOCKED
#
# These are not explicitly allowed above, so they fall through to
# default allow := false. This is defense-in-depth: even with a valid
# token, no one can modify policies or data via the REST API.
# Policies are ONLY loaded from the filesystem (--watch flag).
