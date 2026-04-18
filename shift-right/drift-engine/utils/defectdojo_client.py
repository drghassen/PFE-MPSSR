from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests


@dataclass(frozen=True)
class DefectDojoConfig:
    base_url: str
    api_key: str
    engagement_id: int
    test_title: str
    close_old_findings: bool = True
    deduplication_on_engagement: bool = True
    minimum_severity: str = "Info"
    timeout_s: int = 30


class DefectDojoClient:
    """
    Minimal DefectDojo (v2) client for importing findings.
    """

    def __init__(self, config: DefectDojoConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {config.api_key}",
                "Accept": "application/json",
            }
        )

    def import_scan_generic_findings(
        self, findings: dict[str, Any], scan_date: str
    ) -> dict[str, Any]:
        """
        Import findings using DefectDojo `/api/v2/import-scan/` with `scan_type=Generic Findings Import`.
        """

        url = self.config.base_url.rstrip("/") + "/api/v2/import-scan/"

        data = {
            "scan_type": "Generic Findings Import",
            "engagement": str(self.config.engagement_id),
            "scan_date": scan_date,
            "test_title": self.config.test_title,
            "close_old_findings": "true" if self.config.close_old_findings else "false",
            "deduplication_on_engagement": "true"
            if self.config.deduplication_on_engagement
            else "false",
            "minimum_severity": self.config.minimum_severity,
        }

        content = json.dumps(findings, ensure_ascii=False).encode("utf-8")
        files = {
            "file": ("cloudsentinel-drift-findings.json", content, "application/json")
        }

        response = self.session.post(
            url, data=data, files=files, timeout=self.config.timeout_s
        )
        response.raise_for_status()
        return response.json()
