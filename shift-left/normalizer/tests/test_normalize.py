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


class TestCloudSentinelNormalizer(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
        self.cloud_dir = self.repo_root / ".cloudsentinel"
        self.trivy_raw_dir = self.repo_root / "shift-left" / "trivy" / "reports" / "raw"
        self.cloud_dir.mkdir(parents=True, exist_ok=True)
        self.trivy_raw_dir.mkdir(parents=True, exist_ok=True)

        self.backup_dir = Path(tempfile.mkdtemp(prefix="cs-normalizer-test-"))
        self.tracked_files = [
            self.cloud_dir / "gitleaks_raw.json",
            self.cloud_dir / "checkov_raw.json",
            self.cloud_dir / "golden_report.json",
            self.trivy_raw_dir / "trivy-fs-raw.json",
            self.trivy_raw_dir / "trivy-config-raw.json",
            self.trivy_raw_dir / "trivy-image-raw.json",
        ]
        self.existing = {}
        for src in self.tracked_files:
            bak = self.backup_dir / src.name
            if src.exists():
                shutil.copy2(src, bak)
                self.existing[src] = True
            else:
                self.existing[src] = False

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
        for k, v in self.env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for src in self.tracked_files:
            if self.existing[src]:
                shutil.copy2(self.backup_dir / src.name, src)
            else:
                src.unlink(missing_ok=True)
        shutil.rmtree(self.backup_dir, ignore_errors=True)

    def _write(self, path: Path, payload):
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f)

    def _seed_raw(self, include_trivy=True):
        self._write(self.cloud_dir / "gitleaks_raw.json", [])
        self._write(
            self.cloud_dir / "checkov_raw.json",
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV2_CS_AZ_001",
                            "check_name": "Storage account should disable public access",
                            "resource": "azurerm_storage_account.example",
                            "file_path": "infra/azure/student-secure/main.tf",
                            "file_line_range": [1, 1],
                        }
                    ]
                }
            },
        )
        if include_trivy:
            empty = {"SchemaVersion": 2, "Trivy": {"Version": "0.69.1"}, "Results": []}
            self._write(self.trivy_raw_dir / "trivy-fs-raw.json", empty)
            self._write(self.trivy_raw_dir / "trivy-config-raw.json", empty)
            self._write(self.trivy_raw_dir / "trivy-image-raw.json", empty)
        else:
            (self.trivy_raw_dir / "trivy-fs-raw.json").unlink(missing_ok=True)
            (self.trivy_raw_dir / "trivy-config-raw.json").unlink(missing_ok=True)
            (self.trivy_raw_dir / "trivy-image-raw.json").unlink(missing_ok=True)

    def _generate(self):
        self._seed_raw(include_trivy=True)
        self.CloudSentinelNormalizer().generate()
        with (self.cloud_dir / "golden_report.json").open("r", encoding="utf-8") as f:
            return json.load(f)

    def test_schema_version_present(self):
        report = self._generate()
        self.assertRegex(report["schema_version"], r"^\d+\.\d+\.\d+$")

    def test_findings_is_list(self):
        report = self._generate()
        self.assertIsInstance(report["findings"], list)

    def test_quality_gate_present(self):
        report = self._generate()
        self.assertEqual(report["quality_gate"]["decision"], "NOT_EVALUATED")
        self.assertEqual(report["quality_gate"]["reason"], "evaluation-performed-by-opa-only")

    def test_missing_trivy_emits_not_run(self):
        self._seed_raw(include_trivy=False)
        self.CloudSentinelNormalizer().generate()
        with (self.cloud_dir / "golden_report.json").open("r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(report["scanners"]["trivy"]["status"], "NOT_RUN")

    def test_summary_non_negative(self):
        report = self._generate()
        stats = report["summary"]["global"]
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL", "FAILED", "PASSED", "EXEMPTED"):
            self.assertGreaterEqual(int(stats[key]), 0)


if __name__ == "__main__":
    unittest.main()
