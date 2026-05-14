# CloudInit Pattern Database

`cloudinit_malicious_patterns.json` is the local CloudSentinel pattern database
used by `cloudinit_scan.py` to detect malicious or high-risk VM bootstrap
behavior.

The scanner loads this file by default. You can override it with:

```bash
python3 shift-left/cloudinit-scanner/cloudinit_scan.py \
  --terraform-dir infra/azure \
  --pattern-db shift-left/cloudinit-scanner/rules/cloudinit_malicious_patterns.json
```

or:

```bash
CLOUDINIT_PATTERN_DB=/path/to/patterns.json python3 shift-left/cloudinit-scanner/cloudinit_scan.py
```

Pattern groups:

- `remote_exec_patterns`: remote script execution such as `curl | bash`.
- `security_bypass_patterns`: persistence, firewall disablement, secrets, chmod,
  or other host security bypasses.
- `workload_keywords.database`: DB/runtime intent keywords used for role-spoofing
  detection.

Each pattern must define:

```json
{
  "id": "stable_pattern_id",
  "rule_id": "CS-CLOUDINIT-...",
  "severity": "CRITICAL",
  "message": "Human-readable finding message",
  "regex": "case-insensitive regular expression"
}
```

Keep IDs stable. OPA, tests, and DefectDojo exception correlation may depend on
them.
