#!/usr/bin/env python3
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


def _load_normalizer_class(repo_root: Path):
    module_path = repo_root / "shift-left" / "normalizer" / "normalize.py"
    spec = importlib.util.spec_from_file_location("cloudsentinel_normalizer", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.CloudSentinelNormalizer


def _empty_stats():
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


class TestCloudSentinelNormalizer(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(
            subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        )
        self.cloud_dir = self.repo_root / ".cloudsentinel"
        self.cloud_dir.mkdir(parents=True, exist_ok=True)

        self.backup_dir = Path(tempfile.mkdtemp(prefix="cs-normalizer-test-"))
        self.tracked_files = [
            "gitleaks_opa.json",
            "checkov_opa.json",
            "trivy_opa.json",
            "golden_report.json",
        ]
        self.existing_files = {}
        for name in self.tracked_files:
            src = self.cloud_dir / name
            if src.exists():
                dst = self.backup_dir / name
                shutil.copy2(src, dst)
                self.existing_files[name] = True
            else:
                self.existing_files[name] = False

        self.env_backup = {
            "CLOUDSENTINEL_SCHEMA_STRICT": os.environ.get("CLOUDSENTINEL_SCHEMA_STRICT"),
            "CLOUDSENTINEL_LOCAL_FAST": os.environ.get("CLOUDSENTINEL_LOCAL_FAST"),
            "CLOUDSENTINEL_EXECUTION_MODE": os.environ.get("CLOUDSENTINEL_EXECUTION_MODE"),
            "ENVIRONMENT": os.environ.get("ENVIRONMENT"),
        }
        os.environ["CLOUDSENTINEL_SCHEMA_STRICT"] = "false"
        os.environ["CLOUDSENTINEL_LOCAL_FAST"] = "false"
        os.environ["CLOUDSENTINEL_EXECUTION_MODE"] = "local"
        os.environ["ENVIRONMENT"] = "dev"

        self.CloudSentinelNormalizer = _load_normalizer_class(self.repo_root)

    def tearDown(self):
        for key, value in self.env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

        for name in self.tracked_files:
            target = self.cloud_dir / name
            if self.existing_files.get(name):
                shutil.copy2(self.backup_dir / name, target)
            else:
                target.unlink(missing_ok=True)

        shutil.rmtree(self.backup_dir, ignore_errors=True)

    def _write_json(self, name: str, payload: dict):
        with (self.cloud_dir / name).open("w", encoding="utf-8") as f:
            json.dump(payload, f)

    def _scanner_report(self, tool: str, findings: list):
        total = len(findings)
        return {
            "tool": tool,
            "version": "test",
            "status": "FAILED" if total > 0 else "PASSED",
            "stats": {
                **_empty_stats(),
                "TOTAL": total,
                "FAILED": total,
            },
            "findings": findings,
            "errors": [],
        }

    def _seed_reports(self, include_trivy: bool = True):
        gitleaks_report = self._scanner_report("gitleaks", [])
        checkov_report = self._scanner_report(
            "checkov",
            [
                {
                    "id": "CKV2_CS_AZ_001",
                    "resource": {
                        "name": "azurerm_storage_account.example",
                        "path": "infra/azure/dev/main.tf",
                        "location": {"start_line": 1, "end_line": 1},
                    },
                    "description": "Storage account should disable public access",
                    "severity": "HIGH",
                    "status": "FAILED",
                    "category": "INFRASTRUCTURE_AS_CODE",
                }
            ],
        )
        trivy_report = self._scanner_report("trivy", [])

        self._write_json("gitleaks_opa.json", gitleaks_report)
        self._write_json("checkov_opa.json", checkov_report)
        if include_trivy:
            self._write_json("trivy_opa.json", trivy_report)
        else:
            (self.cloud_dir / "trivy_opa.json").unlink(missing_ok=True)

    def _generate_report(self):
        self._seed_reports(include_trivy=True)
        self.CloudSentinelNormalizer().generate()
        with (self.cloud_dir / "golden_report.json").open("r", encoding="utf-8") as f:
            return json.load(f)

    def test_schema_version_present(self):
        report = self._generate_report()
        self.assertIn("schema_version", report)
        self.assertRegex(report["schema_version"], r"^\d+\.\d+\.\d+$")

    def test_findings_is_list(self):
        report = self._generate_report()
        self.assertIn("findings", report)
        self.assertIsInstance(report["findings"], list)

    def test_quality_gate_present(self):
        report = self._generate_report()
        self.assertIn("quality_gate", report)
        self.assertEqual(report["quality_gate"]["decision"], "NOT_EVALUATED")
        self.assertEqual(report["quality_gate"]["reason"], "evaluation-performed-by-opa-only")

    def test_missing_scanner_emits_not_run(self):
        self._seed_reports(include_trivy=False)
        self.CloudSentinelNormalizer().generate()
        with (self.cloud_dir / "golden_report.json").open("r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report["scanners"]["trivy"]["status"], "NOT_RUN")

    def test_summary_totals_non_negative(self):
        report = self._generate_report()
        stats = report["summary"]["global"]
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL", "FAILED", "PASSED", "EXEMPTED"):
            self.assertGreaterEqual(int(stats[key]), 0)


if __name__ == "__main__":
    unittest.main()
