"""Normalized finding shape, deduplication metadata, and per-scanner stats."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List


class NormalizerFindingMixin:
    def _category(self, f: Dict[str, Any], tool: str) -> str:
        raw = (self._first(f.get("category"), f.get("Category"), "") or "").upper()
        st = (
            self._first(
                f.get("finding_type"), f.get("source", {}).get("scanner_type"), ""
            )
            or ""
        ).lower()
        if tool == "gitleaks":
            return "SECRETS"
        if tool == "checkov":
            return "INFRASTRUCTURE_AS_CODE"
        if raw in {"SECRET", "SECRETS"} or st == "secret":
            return "SECRETS"
        return "VULNERABILITIES"

    def _fingerprint(
        self,
        tool: str,
        rid: str,
        rname: str,
        rpath: str,
        sl: int,
        el: int,
        secret_hash: str,
    ) -> str:
        ctx = "|".join([rpath.lower(), str(sl), str(el), secret_hash.strip().lower()])
        return hashlib.sha256(
            "|".join([tool.lower(), rid.strip().upper(), rname.lower(), ctx]).encode(
                "utf-8"
            )
        ).hexdigest()

    def _normalize_finding(
        self, f: Dict[str, Any], tool: str, version: str, idx: int
    ) -> Dict[str, Any]:
        rid = self._first(
            f.get("id"),
            f.get("rule_id"),
            f.get("RuleID"),
            f.get("VulnerabilityID"),
            "UNKNOWN",
        )
        desc = self._first(
            f.get("description"),
            f.get("message"),
            f.get("title"),
            f.get("check_name"),
            "No description",
        )
        cat = self._category(f, tool)
        rsrc = f.get("resource", {}) if isinstance(f.get("resource"), dict) else {}
        rname = self._first(
            rsrc.get("name"),
            f.get("resource") if isinstance(f.get("resource"), str) else None,
            f.get("file"),
            f.get("target"),
            "unknown",
        )
        rpath = self._norm_path(
            self._first(rsrc.get("path"), f.get("file"), f.get("target"), "unknown")
        )
        meta = f.get("metadata", {}) if isinstance(f.get("metadata"), dict) else {}
        loc = rsrc.get("location", {}) if isinstance(rsrc.get("location"), dict) else {}
        sl = self._to_int(
            loc.get("start_line")
            or f.get("start_line")
            or f.get("line")
            or meta.get("line"),
            0,
        )
        el = self._to_int(
            loc.get("end_line") or f.get("end_line") or meta.get("end_line"), sl
        )
        sd = f.get("severity", {}) if isinstance(f.get("severity"), dict) else {}
        raw_sev = (
            f.get("severity")
            if isinstance(f.get("severity"), str)
            else (sd.get("level") or f.get("original_severity"))
        )
        sev = self.sev_lut.get(str(raw_sev).upper(), "MEDIUM")
        # Status normalization: set once at normalization, immutable downstream.
        # DevSecOps rule: only PASSED (scanner explicit pass, e.g. Trivy misconfig)
        # or FAILED (all detections). EXEMPTED is NOT a valid raw-input status —
        # duplicate tracking lives exclusively in context.deduplication metadata.
        raw_st = str(f.get("status", "FAILED")).upper()
        st = "PASSED" if raw_st == "PASSED" else "FAILED"
        secret_hash = str(meta.get("secret_hash", "")).strip()
        fp = self._fingerprint(tool, str(rid), str(rname), rpath, sl, el, secret_hash)
        fid = f"CS-{tool}-{hashlib.sha256(f'{fp}|{idx}'.encode('utf-8')).hexdigest()[:16]}"
        cvss = sd.get("cvss_score") or f.get("cvss_score") or meta.get("cvss")
        try:
            cvss = float(cvss) if cvss is not None else None
        except Exception:
            cvss = None
        refs = f.get("references") or meta.get("references") or []
        refs = refs if isinstance(refs, list) else []
        # --- Confidence: set once at normalization, never recomputed ---
        # Mapping is deterministic (scanner → confidence level).
        # DevSecOps invariant: confidence is stable between local and CI execution.
        confidence = self._confidence_map.get(tool.lower(), "MEDIUM")
        return {
            "id": fid,
            "confidence": confidence,
            "source": {
                "tool": tool,
                "version": version or "unknown",
                "id": str(rid),
                "scanner_type": self._first(
                    f.get("finding_type"),
                    f.get("source", {}).get("scanner_type"),
                    cat.lower(),
                    "security",
                ),
            },
            "resource": {
                "name": rname,
                "version": self._first(
                    rsrc.get("version"), meta.get("installed_version"), "N/A"
                ),
                "type": self._first(rsrc.get("type"), f.get("finding_type"), "asset"),
                "path": rpath,
                "location": {"file": rpath, "start_line": sl, "end_line": el},
            },
            "description": str(desc),
            "severity": {
                "level": sev,
                "original_severity": self._first(sd.get("level"), raw_sev, "UNKNOWN"),
                "cvss_score": cvss,
            },
            "category": cat,
            "status": st,
            "remediation": {
                "sla_hours": self.sla.get(sev, 720),
                "fix_version": self._first(
                    f.get("fix_version"), meta.get("fixed_version"), "N/A"
                ),
                "references": [str(x) for x in refs],
            },
            "context": {
                "git": {
                    "author_email": self.git_author_email,
                    "commit_date": self.git_commit_date,
                    # True for all non-gitleaks tools (IaC findings always represent current state).
                    # For gitleaks: True = introduced in latest push (blocks), False = historical (advisory).
                    "in_latest_push": bool(meta.get("in_latest_push", True)),
                },
                "deduplication": {
                    "fingerprint": fp,
                    "is_duplicate": False,
                    "duplicate_of": None,
                },
                "traceability": {
                    "source_report": f"{tool}_raw.json",
                    "source_index": idx,
                    "normalized_at": self.ts,
                },
            },
        }

    def _process_scanner(self, data: Dict[str, Any], name: str) -> Dict[str, Any]:
        v = str(data.get("version", "unknown"))
        st = (
            "NOT_RUN"
            if str(data.get("status", "NOT_RUN")).upper() == "NOT_RUN"
            else "OK"
        )
        raws = data.get("findings", [])
        raws = raws if isinstance(raws, list) else []
        return {
            "tool": name,
            "version": v,
            "status": st,
            "errors": [str(x) for x in data.get("errors", [])],
            "stats": self._empty_stats(),
            "findings": [
                self._normalize_finding(f, name, v, i) for i, f in enumerate(raws)
            ],
        }

    def _dedup(self, findings: List[Dict[str, Any]]) -> None:
        """Metadata enrichment pass — marks duplicate findings via context.deduplication.

        DevSecOps contract (non-negotiable):
          - ONLY modifies: context.deduplication.is_duplicate
          - ONLY modifies: context.deduplication.duplicate_of
          - NEVER modifies: status, severity, confidence, category
          - Deduplication = metadata enrichment, NOT state mutation.

        Duplicate signal consumers:
          - OPA: reads `context.deduplication.is_duplicate` (not status) to exclude dupes
          - _stats(): reads `context.deduplication.is_duplicate` for EXEMPTED counter
        """
        seen: Dict[str, str] = {}
        for f in findings:
            d = f.get("context", {}).get("deduplication", {})
            fp = str(d.get("fingerprint", "")).strip()
            if not fp:
                continue
            if fp in seen:
                d["is_duplicate"] = True
                d["duplicate_of"] = seen[fp]
                # status intentionally NOT modified — immutable after normalization.
            else:
                seen[fp] = f.get("id")
                d["is_duplicate"] = False
                d["duplicate_of"] = None

    def _stats(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        s = self._empty_stats()
        for f in findings:
            # Deduplication signal: read from metadata, NOT from status.
            # status is immutable after _normalize_finding(); _dedup() only enriches metadata.
            is_dup = bool(
                f.get("context", {}).get("deduplication", {}).get("is_duplicate", False)
            )
            if is_dup:
                s["EXEMPTED"] += 1
                continue
            st = str(f.get("status", "FAILED")).upper()
            if st == "PASSED":
                s["PASSED"] += 1
                continue
            if st != "FAILED":
                continue
            s["FAILED"] += 1
            s["TOTAL"] += 1
            sev = str(f.get("severity", {}).get("level", "MEDIUM")).upper()
            s[
                sev
                if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
                else "MEDIUM"
            ] += 1
        return s
