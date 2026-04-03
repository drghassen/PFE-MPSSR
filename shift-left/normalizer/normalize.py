#!/usr/bin/env python3
# ==============================================================================
# CloudSentinel Normalizer (Python Edition)
# Description: Merges scanner outputs (Gitleaks, Checkov, Trivy) into a
# unified Golden Report for OPA.
# ==============================================================================

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime


class CloudSentinelNormalizer:
    def __init__(self):
        self.start_time = time.time()
        self.root_dir = self._run_cmd(["git", "rev-parse", "--show-toplevel"], os.getcwd())
        self.output_dir = os.path.join(self.root_dir, ".cloudsentinel")
        self.output_file = os.path.join(self.output_dir, "golden_report.json")
        self.schema_version = "1.1.0"

        self.env = os.environ.get("ENVIRONMENT", os.environ.get("CI_ENVIRONMENT_NAME", "dev")).lower()
        if self.env == "stage":
            self.env = "staging"
        elif self.env not in ["dev", "test", "staging", "prod"]:
            self.env = "dev"

        self.exec_mode = os.environ.get(
            "CLOUDSENTINEL_EXECUTION_MODE", "ci" if "CI" in os.environ else "local"
        ).lower()
        if self.exec_mode not in ["ci", "local", "advisory"]:
            self.exec_mode = "local"

        raw_local_fast = os.environ.get("CLOUDSENTINEL_LOCAL_FAST")
        self.local_fast = (raw_local_fast or "false").lower() == "true"

        self.schema_strict = os.environ.get("CLOUDSENTINEL_SCHEMA_STRICT", "false").lower() == "true"

        # In CI, enforce fixed gate thresholds to prevent bypass via CI variable overrides.
        if os.environ.get("CI"):
            self.critical_max = 0
            self.high_max = 2
        else:
            self.critical_max = self._parse_int(os.environ.get("CRITICAL_MAX"), 0)
            self.high_max = self._parse_int(os.environ.get("HIGH_MAX"), 2)

        self.timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.git_branch = self._run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], "unknown")
        self.git_commit = self._run_cmd(["git", "rev-parse", "HEAD"], "unknown")
        self.git_commit_date = self._run_cmd(["git", "log", "-1", "--format=%cI"], self.timestamp)
        self.git_author_email = self._run_cmd(
            ["git", "log", "-1", "--format=%ae"], "unknown@example.invalid"
        )
        self.pipeline_id = os.environ.get("CI_PIPELINE_ID", "local")

        self.severity_lut = {
            "CRITICAL": "CRITICAL",
            "CRIT": "CRITICAL",
            "SEV5": "CRITICAL",
            "SEVERITY5": "CRITICAL",
            "VERY_HIGH": "CRITICAL",
            "HIGH": "HIGH",
            "SEV4": "HIGH",
            "SEVERITY4": "HIGH",
            "MEDIUM": "MEDIUM",
            "MODERATE": "MEDIUM",
            "SEV3": "MEDIUM",
            "SEVERITY3": "MEDIUM",
            "LOW": "LOW",
            "MINOR": "LOW",
            "SEV2": "LOW",
            "SEVERITY2": "LOW",
            "INFO": "INFO",
            "INFORMATIONAL": "INFO",
            "SEV1": "INFO",
            "SEVERITY1": "INFO",
            "UNKNOWN": "INFO",
        }
        self.sla_map = {"CRITICAL": 24, "HIGH": 168, "MEDIUM": 720, "LOW": 2160, "INFO": 8760}

    def _parse_int(self, val, fallback):
        try:
            return int(val)
        except (TypeError, ValueError):
            return fallback

    def _run_cmd(self, cmd, fallback):
        try:
            return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            return fallback

    def hash_file(self, filepath):
        if not os.path.isfile(filepath):
            return None
        h256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h256.update(chunk)
            return h256.hexdigest()
        except Exception:
            return None

    def _empty_stats(self):
        return {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "TOTAL": 0,
            "EXEMPTED": 0,
            "FAILED": 0,
            "PASSED": 0,
        }

    def _trace_status_from_contract(self, data_status, findings):
        if data_status == "NOT_RUN":
            return "NOT_RUN"
        return "FAILED" if len(findings) > 0 else "PASSED"

    def read_report(self, filepath, tool, skip=False):
        status, reason, checksum, present, valid_json = "NOT_RUN", "", None, False, False
        data = None

        if skip:
            reason = "skipped_local_fast"
        elif os.path.isfile(filepath):
            present = True
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                valid_json = True
                checksum = self.hash_file(filepath)

                if not isinstance(loaded, dict):
                    reason = "invalid_contract:not_object"
                else:
                    required_fields = ["tool", "version", "status", "findings", "errors"]
                    missing = [f for f in required_fields if f not in loaded]
                    if missing:
                        reason = f"invalid_contract_missing_fields:{','.join(missing)}"
                    elif not isinstance(loaded.get("findings"), list):
                        reason = "invalid_contract_findings_not_array"
                    elif not isinstance(loaded.get("errors"), list):
                        reason = "invalid_contract_errors_not_array"
                    else:
                        raw_status = str(loaded.get("status", "")).upper()
                        if raw_status not in ["OK", "NOT_RUN", "PASSED", "FAILED"]:
                            reason = f"invalid_contract_status:{raw_status or 'empty'}"
                        else:
                            status = "NOT_RUN" if raw_status == "NOT_RUN" else "OK"
                            data = loaded
            except Exception:
                reason = "invalid_json"
        else:
            reason = "missing_report"

        if data is None:
            data = {
                "tool": tool,
                "version": "unknown",
                "status": "NOT_RUN",
                "findings": [],
                "errors": [f"{reason}: {filepath}"],
                "stats": self._empty_stats(),
            }
            status = "NOT_RUN"

        trace = {
            "tool": tool,
            "path": filepath,
            "present": present,
            "valid_json": valid_json,
            "status": self._trace_status_from_contract(status, data.get("findings", [])),
            "reason": reason,
            "sha256": checksum,
        }
        return data, trace

    def first_non_empty(self, *args):
        for arg in args:
            if arg is not None and str(arg).strip() != "":
                return str(arg)
        return None

    def norm_path(self, path):
        if not path:
            return "unknown"
        p = str(path).replace("\\", "/").replace("/./", "/")
        while "//" in p:
            p = p.replace("//", "/")
        if p.startswith("./"):
            p = p[2:]
        return p if p else "unknown"

    def canonical_category(self, f, tool):
        raw_cat = self.first_non_empty(f.get("category"), f.get("Category"), "")
        raw_cat = raw_cat.upper() if raw_cat else ""
        stype = self.first_non_empty(f.get("finding_type"), f.get("source", {}).get("scanner_type"), "")
        stype = stype.lower() if stype else ""

        if tool == "gitleaks":
            return "SECRETS"
        if tool == "checkov":
            return "INFRASTRUCTURE_AS_CODE"
        if raw_cat in ["SECRET", "SECRETS"] or stype == "secret":
            return "SECRETS"
        return "VULNERABILITIES"

    def _deterministic_fingerprint(self, tool, raw_id, resource_name, resource_path, start_line, end_line, description):
        normalized_context = "|".join(
            [
                resource_path.lower(),
                str(start_line),
                str(end_line),
                (description or "").strip().lower(),
            ]
        )
        material = "|".join([tool.lower(), str(raw_id).strip().upper(), resource_name.lower(), normalized_context])
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def normalize_finding(self, f, tool, version, idx):
        raw_id = self.first_non_empty(
            f.get("id"), f.get("rule_id"), f.get("RuleID"), f.get("VulnerabilityID"), "UNKNOWN"
        )
        desc = self.first_non_empty(
            f.get("description"), f.get("message"), f.get("title"), f.get("check_name"), "No description"
        )
        category = self.canonical_category(f, tool)

        resource_dict = f.get("resource", {}) if isinstance(f.get("resource"), dict) else {}
        resource_name = self.first_non_empty(
            resource_dict.get("name"),
            f.get("resource") if isinstance(f.get("resource"), str) else None,
            f.get("file"),
            f.get("target"),
            "unknown",
        )
        resource_path = self.norm_path(
            self.first_non_empty(resource_dict.get("path"), f.get("file"), f.get("target"), "unknown")
        )

        meta = f.get("metadata", {}) if isinstance(f.get("metadata"), dict) else {}
        loc = resource_dict.get("location", {}) if isinstance(resource_dict.get("location"), dict) else {}
        start_line = self._parse_int(
            loc.get("start_line") or f.get("start_line") or f.get("line") or meta.get("line"), 0
        )
        end_line = self._parse_int(
            loc.get("end_line") or f.get("end_line") or meta.get("end_line"), start_line
        )

        sev_dict = f.get("severity", {}) if isinstance(f.get("severity"), dict) else {}
        if isinstance(f.get("severity"), str):
            raw_sev_level = f.get("severity")
        else:
            raw_sev_level = sev_dict.get("level") or f.get("original_severity")
        severity_level = self.severity_lut.get(str(raw_sev_level).upper(), "MEDIUM")

        status = str(f.get("status", "FAILED")).upper()
        if status not in ["EXEMPTED", "PASSED"]:
            status = "FAILED"

        fingerprint = self._deterministic_fingerprint(
            tool,
            raw_id,
            str(resource_name),
            resource_path,
            start_line,
            end_line,
            desc,
        )

        unique_hint = hashlib.sha256(f"{fingerprint}|{idx}".encode("utf-8")).hexdigest()[:16]
        finding_id = f"CS-{tool}-{unique_hint}"

        cvss_score = sev_dict.get("cvss_score") or f.get("cvss_score") or meta.get("cvss")
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except ValueError:
            cvss_score = None

        return {
            "id": finding_id,
            "source": {
                "tool": tool,
                "version": version or "unknown",
                "id": raw_id,
                "scanner_type": self.first_non_empty(
                    f.get("finding_type"), f.get("source", {}).get("scanner_type"), category.lower(), "security"
                ),
            },
            "resource": {
                "name": resource_name,
                "version": self.first_non_empty(resource_dict.get("version"), meta.get("installed_version"), "N/A"),
                "type": self.first_non_empty(resource_dict.get("type"), f.get("finding_type"), "asset"),
                "path": resource_path,
                "location": {"file": resource_path, "start_line": start_line, "end_line": end_line},
            },
            "description": desc,
            "severity": {
                "level": severity_level,
                "original_severity": self.first_non_empty(sev_dict.get("level"), raw_sev_level, "UNKNOWN"),
                "cvss_score": cvss_score,
            },
            "category": category,
            "status": status,
            "remediation": {
                "sla_hours": self.sla_map.get(severity_level, 720),
                "fix_version": self.first_non_empty(f.get("fix_version"), meta.get("fixed_version"), "N/A"),
                "references": [str(x) for x in (f.get("references") or meta.get("references") or [])],
            },
            "context": {
                "git": {"author_email": self.git_author_email, "commit_date": self.git_commit_date},
                "deduplication": {
                    "fingerprint": fingerprint,
                    "is_duplicate": False,
                    "duplicate_of": None,
                },
                "traceability": {
                    "source_report": f"{tool}_opa.json",
                    "source_index": idx,
                    "normalized_at": self.timestamp,
                },
            },
        }

    def process_scanner(self, data, name):
        version = str(data.get("version", "unknown"))
        status_raw = str(data.get("status", "NOT_RUN")).upper()
        status = "NOT_RUN" if status_raw == "NOT_RUN" else "OK"

        raw_findings = data.get("findings", [])
        if not isinstance(raw_findings, list):
            raw_findings = []

        norm_findings = [self.normalize_finding(f, name, version, i) for i, f in enumerate(raw_findings)]

        if status == "NOT_RUN":
            norm_findings = []

        return {
            "tool": name,
            "version": version,
            "status": status,
            "errors": [str(x) for x in data.get("errors", [])],
            "stats": self._empty_stats(),
            "findings": norm_findings,
        }

    def mark_duplicates(self, findings):
        first_seen = {}
        for finding in findings:
            dedup = finding.get("context", {}).get("deduplication", {})
            fp = str(dedup.get("fingerprint", "")).strip()
            if not fp:
                continue
            if fp in first_seen:
                dedup["is_duplicate"] = True
                dedup["duplicate_of"] = first_seen[fp]
                # Duplicates are preserved for audit but removed from gate counting.
                finding["status"] = "EXEMPTED"
            else:
                first_seen[fp] = finding.get("id")
                dedup["is_duplicate"] = False
                dedup["duplicate_of"] = None

    def calc_stats(self, findings):
        stats = self._empty_stats()
        for finding in findings:
            status = str(finding.get("status", "FAILED")).upper()
            if status == "EXEMPTED":
                stats["EXEMPTED"] += 1
                continue
            if status == "PASSED":
                stats["PASSED"] += 1
                continue
            if status != "FAILED":
                continue

            stats["FAILED"] += 1
            stats["TOTAL"] += 1
            sev = str(finding.get("severity", {}).get("level", "MEDIUM")).upper()
            if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                stats[sev] += 1
            else:
                stats["MEDIUM"] += 1

        return stats

    def generate(self):
        print("\033[34m[INFO]\033[0m Starting CloudSentinel python normalization process...")

        gitleaks_path = os.path.join(self.output_dir, "gitleaks_opa.json")
        checkov_path = os.path.join(self.output_dir, "checkov_opa.json")
        trivy_path = os.path.join(self.output_dir, "trivy_opa.json")

        gitleaks_data, gitleaks_trace = self.read_report(gitleaks_path, "gitleaks")
        checkov_data, checkov_trace = self.read_report(checkov_path, "checkov", self.local_fast)
        trivy_data, trivy_trace = self.read_report(trivy_path, "trivy", self.local_fast)

        scanners = {
            "gitleaks": self.process_scanner(gitleaks_data, "gitleaks"),
            "checkov": self.process_scanner(checkov_data, "checkov"),
            "trivy": self.process_scanner(trivy_data, "trivy"),
        }

        all_findings = (
            scanners["gitleaks"]["findings"]
            + scanners["checkov"]["findings"]
            + scanners["trivy"]["findings"]
        )

        self.mark_duplicates(all_findings)

        # Recompute per-scanner stats after dedup tagging.
        for scanner in scanners.values():
            scanner["stats"] = self.calc_stats(scanner["findings"])
            if scanner["status"] == "NOT_RUN":
                scanner["status"] = "NOT_RUN"
            elif scanner["stats"]["TOTAL"] > 0:
                scanner["status"] = "FAILED"
            else:
                scanner["status"] = "PASSED"

        global_stats = self.calc_stats(all_findings)

        c_sec = c_iac = c_vuln = 0
        for finding in all_findings:
            if str(finding.get("status", "FAILED")).upper() != "FAILED":
                continue
            cat = finding.get("category")
            if cat == "SECRETS":
                c_sec += 1
            elif cat == "INFRASTRUCTURE_AS_CODE":
                c_iac += 1
            elif cat == "VULNERABILITIES":
                c_vuln += 1

        summary = {
            "global": global_stats,
            "by_tool": {k: {**v["stats"], "status": v["status"]} for k, v in scanners.items()},
            "by_category": {
                "SECRETS": c_sec,
                "INFRASTRUCTURE_AS_CODE": c_iac,
                "VULNERABILITIES": c_vuln,
            },
        }

        not_run_scanners = [k for k, v in scanners.items() if v["status"] == "NOT_RUN"]

        report = {
            "schema_version": self.schema_version,
            "metadata": {
                "tool": "cloudsentinel",
                "timestamp": self.timestamp,
                "generation_duration_ms": 0,
                "environment": self.env.lower(),
                "execution": {"mode": self.exec_mode},
                "git": {
                    "branch": self.git_branch,
                    "commit": self.git_commit,
                    "commit_date": self.git_commit_date,
                    "author_email": self.git_author_email,
                    "pipeline_id": self.pipeline_id,
                },
                "normalizer": {
                    "version": self.schema_version,
                    "source_reports": {
                        "gitleaks": gitleaks_trace,
                        "checkov": checkov_trace,
                        "trivy": trivy_trace,
                    },
                },
            },
            "scanners": scanners,
            "findings": all_findings,
            "summary": summary,
            "quality_gate": {
                "decision": "NOT_EVALUATED",
                "reason": "evaluation-performed-by-opa-only",
                "thresholds": {"critical_max": self.critical_max, "high_max": self.high_max},
                "details": {
                    "reasons": ["opa_is_single_enforcement_point"],
                    "not_run_scanners": not_run_scanners,
                },
            },
        }

        report["metadata"]["generation_duration_ms"] = int((time.time() - self.start_time) * 1000)

        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print("\033[34m[INFO]\033[0m Starting schema validation...")
        val_start = time.time()
        self._validate_schema(report)
        val_end = time.time()
        print(f"\033[34m[INFO]\033[0m Schema validation took {(val_end - val_start) * 1000:.2f} ms")

        print(f"\033[34m[INFO]\033[0m Golden Report generated successfully: {self.output_file}")
        print("\033[34m[INFO]\033[0m OPA input ready -> run 'bash shift-left/opa/run-opa.sh --enforce' for the gate decision.")

    def _validate_schema(self, report):
        schema_path = os.path.join(
            self.root_dir, "shift-left", "normalizer", "schema", "cloudsentinel_report.schema.json"
        )
        try:
            from jsonschema import Draft7Validator, validate

            if os.path.isfile(schema_path):
                with open(schema_path, "r", encoding="utf-8") as sf:
                    schema = json.load(sf)
                Draft7Validator.check_schema(schema)
                validate(report, schema)
        except ImportError:
            msg = "jsonschema module missing. "
            if self.schema_strict:
                print(f"\033[31m[ERROR]\033[0m {msg}Strict mode requires it.", file=sys.stderr)
                sys.exit(1)
            print(f"\033[33m[WARN]\033[0m {msg}Schema validation skipped.", file=sys.stderr)
        except Exception as e:
            print(f"\033[31m[ERROR]\033[0m Golden report schema validation failed: {str(e)}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    CloudSentinelNormalizer().generate()