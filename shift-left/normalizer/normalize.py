#!/usr/bin/env python3
# ==============================================================================
# CloudSentinel Normalizer (Python Edition)
# Description: Merges scanner outputs (Gitleaks, Checkov, Trivy) into a
#              unified Golden Report for OPA perfectly formatted and extremely fast.
# ==============================================================================

import json
import os
import sys
import hashlib
import time
import subprocess
from datetime import datetime

class CloudSentinelNormalizer:
    def __init__(self):
        self.start_time = time.time()
        self.root_dir = self._run_cmd(["git", "rev-parse", "--show-toplevel"], os.getcwd())
        self.output_dir = os.path.join(self.root_dir, ".cloudsentinel")
        self.output_file = os.path.join(self.output_dir, "golden_report.json")
        self.schema_version = "1.1.0"
        
        self.env = os.environ.get("ENVIRONMENT", os.environ.get("CI_ENVIRONMENT_NAME", "dev")).lower()
        if self.env == "stage": self.env = "staging"
        elif self.env not in ["dev", "test", "staging", "prod"]: self.env = "dev"
        
        self.exec_mode = os.environ.get("CLOUDSENTINEL_EXECUTION_MODE", "ci" if "CI" in os.environ else "local").lower()
        if self.exec_mode not in ["ci", "local", "advisory"]: self.exec_mode = "local"
        
        raw_local_fast = os.environ.get("CLOUDSENTINEL_LOCAL_FAST")
        if raw_local_fast is None:
            self.local_fast = False
        else:
            self.local_fast = raw_local_fast.lower() == "true"
            
        self.schema_strict = os.environ.get("CLOUDSENTINEL_SCHEMA_STRICT", "false").lower() == "true"
        
        self.critical_max = self._parse_int(os.environ.get("CRITICAL_MAX"), 0)
        self.high_max = self._parse_int(os.environ.get("HIGH_MAX"), 2)
        
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.git_branch = self._run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], "unknown")
        self.git_commit = self._run_cmd(["git", "rev-parse", "HEAD"], "unknown")
        self.git_commit_date = self._run_cmd(["git", "log", "-1", "--format=%cI"], self.timestamp)
        self.git_author_email = self._run_cmd(["git", "log", "-1", "--format=%ae"], "unknown@example.invalid")
        self.pipeline_id = os.environ.get("CI_PIPELINE_ID", "local")

        self.severity_lut = {
            "CRITICAL": "CRITICAL", "CRIT": "CRITICAL", "SEV5": "CRITICAL", "SEVERITY5": "CRITICAL", "VERY_HIGH": "CRITICAL",
            "HIGH": "HIGH", "SEV4": "HIGH", "SEVERITY4": "HIGH",
            "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "SEV3": "MEDIUM", "SEVERITY3": "MEDIUM",
            "LOW": "LOW", "MINOR": "LOW", "SEV2": "LOW", "SEVERITY2": "LOW",
            "INFO": "INFO", "INFORMATIONAL": "INFO", "SEV1": "INFO", "SEVERITY1": "INFO", "UNKNOWN": "INFO"
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
        if not os.path.isfile(filepath): return None
        h256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h256.update(chunk)
            return h256.hexdigest()
        except Exception:
            return None

    def read_report(self, filepath, tool, skip=False):
        status, reason, checksum, present, valid_json = "NOT_RUN", "", None, False, False
        data = None

        if skip:
            reason = "skipped_local_fast"
        elif os.path.isfile(filepath):
            present = True
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                valid_json = True
                checksum = self.hash_file(filepath)
                
                raw_status = str(data.get("status", "")).upper()
                if raw_status in ["PASSED", "FAILED", "EXEMPTED", "NOT_RUN"]:
                    status = raw_status
                else:
                    if data.get("has_findings", False) or data.get("stats", {}).get("TOTAL", 0) > 0:
                        status = "FAILED"
                    else:
                        status = "PASSED"
            except Exception:
                reason = "invalid_json"
        else:
            reason = "missing_report"

        if data is None:
            data = {
                "tool": tool, "version": "unknown", "status": "NOT_RUN",
                "stats": {k: 0 for k in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","TOTAL","EXEMPTED","FAILED","PASSED"]} | {"error": True},
                "findings": [], "errors": [f"{reason}: {filepath}"]
            }

        trace = {
            "tool": tool, "path": filepath, "present": present, "valid_json": valid_json,
            "status": status, "reason": reason, "sha256": checksum
        }
        return data, trace

    def first_non_empty(self, *args):
        for arg in args:
            if arg is not None and str(arg).strip() != "":
                return str(arg)
        return None

    def norm_path(self, path):
        if not path: return "unknown"
        p = str(path).replace("\\", "/").replace("/./", "/")
        while "//" in p: p = p.replace("//", "/")
        if p.startswith("./"): p = p[2:]
        return p if p else "unknown"

    def canonical_category(self, f, tool):
        raw_cat = self.first_non_empty(f.get("category"), f.get("Category"), "")
        raw_cat = raw_cat.upper() if raw_cat else ""
        stype = self.first_non_empty(f.get("finding_type"), f.get("source", {}).get("scanner_type"), "")
        stype = stype.lower() if stype else ""
        
        if tool == "gitleaks": return "SECRETS"
        if tool == "checkov": return "INFRASTRUCTURE_AS_CODE"
        if raw_cat in ["SECRET", "SECRETS"] or stype == "secret": return "SECRETS"
        return "VULNERABILITIES"

    def normalize_finding(self, f, tool, version, idx):
        raw_id = self.first_non_empty(f.get("id"), f.get("rule_id"), f.get("RuleID"), f.get("VulnerabilityID"), "UNKNOWN")
        desc = self.first_non_empty(f.get("description"), f.get("message"), f.get("title"), f.get("check_name"), "No description")
        category = self.canonical_category(f, tool)
        
        resource_dict = f.get("resource", {}) if isinstance(f.get("resource"), dict) else {}
        resource_name = self.first_non_empty(resource_dict.get("name"), f.get("resource") if isinstance(f.get("resource"), str) else None, f.get("file"), f.get("target"), "unknown")
        resource_path = self.norm_path(self.first_non_empty(resource_dict.get("path"), f.get("file"), f.get("target"), "unknown"))
        
        meta = f.get("metadata", {})
        loc = resource_dict.get("location", {})
        start_line = self._parse_int(loc.get("start_line") or f.get("start_line") or f.get("line") or meta.get("line"), 0)
        end_line = self._parse_int(loc.get("end_line") or f.get("end_line") or meta.get("end_line"), start_line)
        
        sev_dict = f.get("severity", {}) if isinstance(f.get("severity"), dict) else {}
        raw_sev_level = sev_dict.get("level") or f.get("severity") if isinstance(f.get("severity"), str) else f.get("original_severity")
        severity_level = self.severity_lut.get(str(raw_sev_level).upper(), "MEDIUM")
        
        status = str(f.get("status", "FAILED")).upper()
        if status not in ["EXEMPTED", "PASSED"]: status = "FAILED"
        
        dedup = f.get("context", {}).get("deduplication", {})
        fingerprint = self.first_non_empty(dedup.get("fingerprint"), f.get("fingerprint"), f"fp:{tool}|{raw_id}|{resource_path}|{start_line}")
        cvss_score = sev_dict.get("cvss_score") or f.get("cvss_score") or meta.get("cvss")
        try: cvss_score = float(cvss_score) if cvss_score is not None else None
        except ValueError: cvss_score = None

        return {
            "id": f"CS-{tool}-{raw_id}",
            "source": {
                "tool": tool, "version": version or "unknown", "id": raw_id,
                "scanner_type": self.first_non_empty(f.get("finding_type"), f.get("source", {}).get("scanner_type"), category.lower(), "security")
            },
            "resource": {
                "name": resource_name,
                "version": self.first_non_empty(resource_dict.get("version"), meta.get("installed_version"), "N/A"),
                "type": self.first_non_empty(resource_dict.get("type"), f.get("finding_type"), "asset"),
                "path": resource_path,
                "location": {"file": resource_path, "start_line": start_line, "end_line": end_line}
            },
            "description": desc,
            "severity": {
                "level": severity_level,
                "original_severity": self.first_non_empty(sev_dict.get("level"), raw_sev_level, "UNKNOWN"),
                "cvss_score": cvss_score
            },
            "category": category,
            "status": status,
            "remediation": {
                "sla_hours": self.sla_map.get(severity_level, 720),
                "fix_version": self.first_non_empty(f.get("fix_version"), meta.get("fixed_version"), "N/A"),
                "references": [str(x) for x in (f.get("references") or meta.get("references") or [])]
            },
            "context": {
                "git": {"author_email": self.git_author_email, "commit_date": self.git_commit_date},
                "deduplication": {"fingerprint": fingerprint, "is_duplicate": False, "duplicate_of": None},
                "traceability": {
                    "source_report": f"{tool}_opa.json", "source_index": idx, "normalized_at": self.timestamp
                }
            }
        }

    def process_scanner(self, data, name):
        version = data.get("version", "unknown")
        raw_findings = data.get("findings", [])
        if not isinstance(raw_findings, list): raw_findings = []
        
        norm_findings = []
        failed = exempted = passed = 0
        crit = high = med = low = info = 0
        
        for i, f in enumerate(raw_findings):
            norm_f = self.normalize_finding(f, name, version, i)
            norm_findings.append(norm_f)
            
            st = norm_f["status"]
            if st == "FAILED":
                failed += 1
                lvl = norm_f["severity"]["level"]
                if lvl == "CRITICAL": crit += 1
                elif lvl == "HIGH": high += 1
                elif lvl == "MEDIUM": med += 1
                elif lvl == "LOW": low += 1
                elif lvl == "INFO": info += 1
            elif st == "EXEMPTED": exempted += 1
            elif st == "PASSED": passed += 1
        
        status_raw = str(data.get("status", "")).upper()
        if status_raw == "NOT_RUN": final_status = "NOT_RUN"
        elif status_raw == "PASSED": final_status = "PASSED"
        elif status_raw == "FAILED" or failed > 0: final_status = "FAILED"
        else: final_status = "PASSED"

        return {
            "tool": name, "version": version, "status": final_status,
            "errors": [str(x) for x in data.get("errors", [])],
            "stats": {
                "CRITICAL": crit, "HIGH": high, "MEDIUM": med, "LOW": low, "INFO": info,
                "TOTAL": failed, "EXEMPTED": exempted, "FAILED": failed, "PASSED": passed
            },
            "findings": norm_findings
        }

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
            "trivy": self.process_scanner(trivy_data, "trivy")
        }

        all_findings = scanners["gitleaks"]["findings"] + scanners["checkov"]["findings"] + scanners["trivy"]["findings"]
        
        g_crit = g_high = g_med = g_low = g_info = 0
        g_failed = g_exempted = g_passed = 0
        c_sec = c_iac = c_vuln = 0
        
        for f in all_findings:
            st = f["status"]
            if st == "FAILED":
                g_failed += 1
                lvl = f["severity"]["level"]
                if lvl == "CRITICAL": g_crit += 1
                elif lvl == "HIGH": g_high += 1
                elif lvl == "MEDIUM": g_med += 1
                elif lvl == "LOW": g_low += 1
                elif lvl == "INFO": g_info += 1
                
                cat = f["category"]
                if cat == "SECRETS": c_sec += 1
                elif cat == "INFRASTRUCTURE_AS_CODE": c_iac += 1
                elif cat == "VULNERABILITIES": c_vuln += 1
            elif st == "EXEMPTED":
                g_exempted += 1
            elif st == "PASSED":
                g_passed += 1
        
        summary = {
            "global": {
                "CRITICAL": g_crit, "HIGH": g_high, "MEDIUM": g_med, "LOW": g_low, "INFO": g_info,
                "TOTAL": g_failed, "EXEMPTED": g_exempted, "FAILED": g_failed, "PASSED": g_passed
            },
            "by_tool": {k: {**v["stats"], "status": v["status"]} for k, v in scanners.items()},
            "by_category": {
                "SECRETS": c_sec,
                "INFRASTRUCTURE_AS_CODE": c_iac,
                "VULNERABILITIES": c_vuln
            }
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
                    "branch": self.git_branch, "commit": self.git_commit, "commit_date": self.git_commit_date,
                    "author_email": self.git_author_email, "pipeline_id": self.pipeline_id
                },
                "normalizer": {
                    "version": self.schema_version,
                    "source_reports": {"gitleaks": gitleaks_trace, "checkov": checkov_trace, "trivy": trivy_trace}
                }
            },
            "scanners": scanners,
            "findings": all_findings,
            "summary": summary,
            "quality_gate": {
                "decision": "NOT_EVALUATED",
                "reason": "evaluation-performed-by-opa-only",
                "thresholds": {"critical_max": self.critical_max, "high_max": self.high_max},
                "details": {"reasons": ["opa_is_single_enforcement_point"], "not_run_scanners": not_run_scanners}
            }
        }

        report["metadata"]["generation_duration_ms"] = int((time.time() - self.start_time) * 1000)

        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"\033[34m[INFO]\033[0m Starting schema validation...")
        val_start = time.time()
        self._validate_schema(report)
        val_end = time.time()
        print(f"\033[34m[INFO]\033[0m Schema validation took {(val_end - val_start)*1000:.2f} ms")

        print(f"\033[34m[INFO]\033[0m Golden Report generated successfully: {self.output_file}")
        print("\033[34m[INFO]\033[0m OPA input ready → run 'bash shift-left/opa/run-opa.sh --enforce' for the gate decision.")

    def _validate_schema(self, report):
        schema_path = os.path.join(self.root_dir, "shift-left", "normalizer", "schema", "cloudsentinel_report.schema.json")
        try:
            from jsonschema import validate, Draft7Validator
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
            else:
                print(f"\033[33m[WARN]\033[0m {msg}Schema validation skipped.", file=sys.stderr)
        except Exception as e:
            print(f"\033[31m[ERROR]\033[0m Golden report schema validation failed: {str(e)}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    CloudSentinelNormalizer().generate()
