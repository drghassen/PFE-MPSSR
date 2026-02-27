# Technical Contract: CloudSentinel Normalizer ↔ OPA

This document defines the interface between the **Normalizer** (Data Producer) and **Open Policy Agent** (Data Consumer/Decision Point).

## 1. Golden Report Specification
The Normalizer MUST produce a JSON object (Golden Report) that adheres to the following structural requirements for consumption by OPA.

### 1.1 Metadata Layer
- `metadata.environment`: Must be one of `dev`, `test`, `staging`, `prod`.
- `metadata.execution.mode`: Must be `ci`, `local`, or `advisory`.

### 1.2 Severity Contract (Critical)
OPA expects finding severity to be a **Nested Object** for rich evaluation, but MUST handle legacy string formats for backward compatibility.

**Standard Format (Object):**
```json
"severity": {
  "level": "CRITICAL",
  "original_severity": "very-high",
  "cvss_score": 9.8
}
```

**Legacy/Defensive Format (String):**
```json
"severity": "CRITICAL"
```

> [!IMPORTANT]
> OPA policies must use the `finding_severity_level(f)` helper function to extract the level regardless of the input format.

## 2. Decision Logic
- **Allow:** `count(deny) == 0`
- **Deny:** `effective_critical > threshold.critical_max` OR `effective_high > threshold.high_max`.

## 3. Exceptions
Exceptions are matched against findings using:
1. `rule_id`
2. `resource_path` OR `resource_name`
3. `tool`
4. `environment`
