#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow sibling imports when executed as a script or loaded via importlib (tests).
_NORM_DIR = str(Path(__file__).resolve().parent)
if _NORM_DIR not in sys.path:
    sys.path.insert(0, _NORM_DIR)

from cs_norm_constants import (  # noqa: E402
    DB_PORTS,
    DEFAULT_CONFIDENCE_MAP,
    DEFAULT_SEV_LUT,
    DEFAULT_SLA,
)
from cs_norm_finding import NormalizerFindingMixin  # noqa: E402
from cs_norm_mappings import NormalizerMappingMixin  # noqa: E402
from cs_norm_raw_parsers import NormalizerRawParsersMixin  # noqa: E402
from cs_norm_utils import NormalizerUtilsMixin  # noqa: E402

__all__ = ["CloudSentinelNormalizer", "DB_PORTS"]


class CloudSentinelNormalizer(
    NormalizerUtilsMixin,
    NormalizerMappingMixin,
    NormalizerRawParsersMixin,
    NormalizerFindingMixin,
):
    def __init__(self):
        self.start_time = time.time()
        self.root = Path(
            self._run(["git", "rev-parse", "--show-toplevel"], os.getcwd())
        )
        self.out_dir = self.root / ".cloudsentinel"
        self.out_file = self.out_dir / "golden_report.json"
        self.schema_version = "1.3.0"

        # Confidence map: deterministic, scanner-type-based.
        # DevSecOps contract: confidence MUST be set here, NEVER recomputed downstream.
        # Invariant: local == CI (no runtime dependency, no env var influence).
        self._confidence_map: Dict[str, str] = dict(DEFAULT_CONFIDENCE_MAP)

        self.env = os.environ.get(
            "ENVIRONMENT", os.environ.get("CI_ENVIRONMENT_NAME", "dev")
        ).lower()
        self.env = "staging" if self.env == "stage" else self.env
        if self.env not in {"dev", "test", "staging", "prod"}:
            self.env = "dev"

        self.exec_mode = os.environ.get(
            "CLOUDSENTINEL_EXECUTION_MODE", "ci" if "CI" in os.environ else "local"
        ).lower()
        if self.exec_mode not in {"ci", "local", "advisory"}:
            self.exec_mode = "local"
        self.local_fast = (
            os.environ.get("CLOUDSENTINEL_LOCAL_FAST", "false").lower() == "true"
        )
        _def_strict = "true" if os.environ.get("CI") else "false"
        self.schema_strict = (
            os.environ.get("CLOUDSENTINEL_SCHEMA_STRICT", _def_strict).lower() == "true"
        )

        self.critical_max = self._to_int(os.environ.get("CRITICAL_MAX"), 0)
        self.high_max = self._to_int(os.environ.get("HIGH_MAX"), 2)

        self.ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.git_branch = os.environ.get("CI_COMMIT_REF_NAME", "").strip() or self._run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], "unknown"
        )
        self.git_commit = os.environ.get("CI_COMMIT_SHA", "").strip() or self._run(
            ["git", "rev-parse", "HEAD"], "unknown"
        )
        self.git_commit_date = os.environ.get("CI_COMMIT_TIMESTAMP", "").strip() or self._run(
            ["git", "log", "-1", "--format=%cI"], self.ts
        )
        self.git_author_email = os.environ.get("GITLAB_USER_EMAIL", "").strip() or self._run(
            ["git", "log", "-1", "--format=%ae"], "unknown@example.invalid"
        )
        self.pipeline_id = os.environ.get("CI_PIPELINE_ID", "local")
        self.git_repo = self._resolve_repo()

        self.sev_lut = dict(DEFAULT_SEV_LUT)
        self.sla = dict(DEFAULT_SLA)
        self._checkov_map: Optional[Dict[str, Dict[str, str]]] = None
        self._gitleaks_sev_map: Optional[Dict[str, str]] = None

    def _load_cloudinit_resources(self) -> List[Dict[str, Any]]:
        default_path = self.root / ".cloudsentinel" / "cloudinit_analysis.json"
        cloudinit_path = Path(
            os.environ.get("CLOUDINIT_ANALYSIS_JSON", str(default_path))
        )

        try:
            resolved = cloudinit_path.resolve(strict=False)
            resolved.relative_to(self.root.resolve())
        except (OSError, ValueError):
            print(
                f"\033[31m[ERROR]\033[0m Cloud-init analysis path outside repo — rejected: {cloudinit_path}",
                file=sys.stderr,
            )
            return []

        if not resolved.is_file():
            return []

        try:
            with resolved.open("r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception as e:
            print(
                f"\033[33m[WARN]\033[0m Cloud-init analysis unreadable ({resolved}): {e}"
            )
            return []

        resources = doc.get("resources_analyzed", [])
        if isinstance(resources, list):
            return [r for r in resources if isinstance(r, dict)]
        return []

    def generate(self):
        print(
            "\033[34m[INFO]\033[0m Starting CloudSentinel normalization (raw ingestion)..."
        )
        skip = self.local_fast and self.exec_mode in {"local", "advisory"}
        g_data, g_trace = self._parse_gitleaks(skip=False)
        c_data, c_trace = self._parse_checkov(skip=skip)
        t_data, t_trace = self._parse_trivy(skip=skip)
        # Cloud-init scanner: parsed as 4th first-class scanner.
        # Violations enter the standard findings[] array so that:
        #   (1) CRITICAL/HIGH counters in summary include cloud-init violations,
        #   (2) thresholds CRITICAL_MAX / HIGH_MAX are enforced uniformly,
        #   (3) DefectDojo upload covers cloud-init findings,
        #   (4) deduplication SHA256 fingerprints are computed.
        # resources_analyzed is PRESERVED in the report for OPA multi-signal
        # correlation (gate_deny_intent.rego reads it directly via input.resources_analyzed).
        ci_data, ci_trace = self._parse_cloudinit(skip=skip)
        resources_analyzed = self._load_cloudinit_resources()

        scanners = {
            "gitleaks": self._process_scanner(g_data, "gitleaks"),
            "checkov": self._process_scanner(c_data, "checkov"),
            "trivy": self._process_scanner(t_data, "trivy"),
            "cloudinit": self._process_scanner(ci_data, "cloudinit"),
        }
        findings = (
            scanners["gitleaks"]["findings"]
            + scanners["checkov"]["findings"]
            + scanners["trivy"]["findings"]
            + scanners["cloudinit"]["findings"]
        )
        self._dedup(findings)
        src_map = {
            "gitleaks": g_data,
            "checkov": c_data,
            "trivy": t_data,
            "cloudinit": ci_data,
        }
        for nm, sc in scanners.items():
            sc["stats"] = self._stats(sc["findings"])
            src = src_map[nm]
            if str(src.get("status", "OK")).upper() == "NOT_RUN":
                sc["status"] = "NOT_RUN"
            elif sc["stats"]["TOTAL"] > 0:
                sc["status"] = "FAILED"
            else:
                sc["status"] = "PASSED"

        by_cat = {"SECRETS": 0, "INFRASTRUCTURE_AS_CODE": 0, "VULNERABILITIES": 0}
        for f in findings:
            if str(f.get("status", "FAILED")).upper() == "FAILED":
                c = str(f.get("category", "VULNERABILITIES"))
                if c in by_cat:
                    by_cat[c] += 1
        summary = {
            "global": self._stats(findings),
            "by_tool": {
                k: {**v["stats"], "status": v["status"]} for k, v in scanners.items()
            },
            "by_category": by_cat,
        }
        not_run = [k for k, v in scanners.items() if v["status"] == "NOT_RUN"]

        report = {
            "schema_version": self.schema_version,
            "metadata": {
                "tool": "cloudsentinel",
                "timestamp": self.ts,
                "generation_duration_ms": 0,
                "environment": self.env,
                "execution": {"mode": self.exec_mode},
                "git": {
                    "repository": self.git_repo,
                    "branch": self.git_branch,
                    "commit": self.git_commit,
                    "commit_date": self.git_commit_date,
                    "author_email": self.git_author_email,
                    "pipeline_id": self.pipeline_id,
                },
                "normalizer": {
                    "version": self.schema_version,
                    "compatibility": "backward",
                    "source_reports": {
                        "gitleaks": g_trace,
                        "checkov": c_trace,
                        "trivy": t_trace,
                        "cloudinit": ci_trace,
                    },
                },
            },
            "scanners": scanners,
            "findings": findings,
            "summary": summary,
            "quality_gate": {
                "thresholds": {
                    "critical_max": self.critical_max,
                    "high_max": self.high_max,
                },
                "details": {
                    "not_run_scanners": not_run,
                },
            },
            # resources_analyzed: preserved for OPA multi-signal correlation.
            # gate_deny_intent.rego reads input.resources_analyzed directly for
            # CS-MULTI-SIGNAL-ROLE-SPOOFING-V2 (requires 3 independent signals).
            # This field is METADATA ONLY — enforcement is via findings[] + OPA.
            "resources_analyzed": resources_analyzed,
        }
        report["metadata"]["generation_duration_ms"] = int(
            (time.time() - self.start_time) * 1000
        )

        self.out_dir.mkdir(parents=True, exist_ok=True)
        with self.out_file.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        self._validate_schema(report)
        print(
            f"\033[34m[INFO]\033[0m Golden Report generated successfully: {self.out_file}"
        )

    def _validate_schema(self, report: Dict[str, Any]):
        schema_path = (
            self.root
            / "shift-left"
            / "normalizer"
            / "schema"
            / "cloudsentinel_report.schema.json"
        )
        try:
            from jsonschema import Draft7Validator, validate

            if schema_path.is_file():
                with schema_path.open("r", encoding="utf-8") as f:
                    schema = json.load(f)
                Draft7Validator.check_schema(schema)
                validate(report, schema)
        except ImportError:
            if self.schema_strict:
                print(
                    "\033[31m[ERROR]\033[0m jsonschema module missing in strict mode",
                    file=sys.stderr,
                )
                sys.exit(1)
        except Exception as e:
            print(
                f"\033[31m[ERROR]\033[0m Golden report schema validation failed: {e}",
                file=sys.stderr,
            )
            sys.exit(1)


if __name__ == "__main__":
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    CloudSentinelNormalizer().generate()
