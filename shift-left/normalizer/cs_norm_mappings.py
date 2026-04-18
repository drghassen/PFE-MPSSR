"""Lazy-loaded Checkov / Gitleaks severity mappings."""

from __future__ import annotations

import re
from typing import Dict


class NormalizerMappingMixin:
    def _checkov_mapping(self) -> Dict[str, Dict[str, str]]:
        if self._checkov_map is not None:
            return self._checkov_map
        p = self.root / "shift-left" / "checkov" / "policies" / "mapping.json"
        doc, err = self._read_json(p)
        if err or not isinstance(doc, dict):
            self._checkov_map = {}
            return self._checkov_map
        out: Dict[str, Dict[str, str]] = {}
        for k, v in doc.items():
            if isinstance(v, dict):
                out[str(k)] = {"category": str(v.get("category", "UNKNOWN")), "severity": str(v.get("severity", "MEDIUM")).upper()}
        self._checkov_map = out
        return out

    def _gitleaks_mapping(self) -> Dict[str, str]:
        if self._gitleaks_sev_map is not None:
            return self._gitleaks_sev_map
        p = self.root / "shift-left" / "gitleaks" / "gitleaks.toml"
        if not p.is_file():
            self._gitleaks_sev_map = {}
            return {}
        cur: Dict[str, str] = {}
        out: Dict[str, str] = {}

        def flush():
            rid = cur.get("id", "").strip()
            if not rid:
                return
            sev = cur.get("severity", "").strip().upper()
            tags = cur.get("tags", "").lower()
            if not sev:
                sev = "CRITICAL" if "critical" in tags else "HIGH" if "high" in tags else "MEDIUM" if "medium" in tags else "LOW" if "low" in tags else "INFO" if ("info" in tags or "informational" in tags) else "HIGH"
            out[rid] = self.sev_lut.get(sev, "HIGH")

        for line in p.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("[[rules]]"):
                flush()
                cur = {}
            elif s.startswith("id"):
                m = re.search(r'=\s*"([^"]+)"', s)
                if m:
                    cur["id"] = m.group(1)
            elif s.startswith("severity"):
                m = re.search(r'=\s*"([^"]+)"', s)
                if m:
                    cur["severity"] = m.group(1)
            elif s.startswith("tags"):
                cur["tags"] = s
        flush()
        self._gitleaks_sev_map = out
        return out
