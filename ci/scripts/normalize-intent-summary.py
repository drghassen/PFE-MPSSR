#!/usr/bin/env python3
"""CloudSentinel CI — Intent Contract Summary (post-normalize display)."""
import json
import sys

try:
    report = json.load(open(".cloudsentinel/golden_report.json", encoding="utf-8"))
except Exception as e:
    print(f"[intent-summary][ERROR] Cannot read golden_report.json: {e}", flush=True)
    sys.exit(1)

intent = report.get("intent_contract") or {}
mismatches = report.get("intent_mismatches") or []

print("", flush=True)
print("\u2501" * 60, flush=True)
print("[INTENT CONTRACT SUMMARY]", flush=True)

if intent.get("violation"):
    print(f"  STATUS   : VIOLATION \u2014 {intent['violation']}", flush=True)
    print("\u2501" * 60, flush=True)
    sys.exit(1)

declared = intent.get("declared") or {}
print(f"  STATUS   : Contrat present", flush=True)
print(f"  Type     : {declared.get('service_type')}", flush=True)
print(f"  Exposure : {declared.get('exposure_level')}", flush=True)
print(f"  Owner    : {declared.get('owner')}", flush=True)
print(f"  Approver : {declared.get('approved_by')}", flush=True)

if mismatches:
    print(f"  WARNING  : {len(mismatches)} mismatch(es) detecte(s):", flush=True)
    for m in mismatches:
        print(f"    -> {m.get('rule')} | {m.get('observed')}", flush=True)
        print(f"       MITRE: {m.get('mitre')}", flush=True)
else:
    print("  Mismatches : Aucun", flush=True)

print("\u2501" * 60, flush=True)
